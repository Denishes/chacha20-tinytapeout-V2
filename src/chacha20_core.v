`default_nettype none

// ChaCha20: one complete quarter-round per clock.
//
// 80 processing cycles + 1 final feed-forward/XOR cycle.
// Latency: 81 clock periods from accepted start to done.
// Minimum initiation interval: 82 clock periods.
//
// Inputs are captured when start is high in ST_IDLE.
// start is ignored while processing.
// done pulses for one cycle.
// data_out holds its value until the next result or reset.
//
// Synchronous active-high reset aborts the operation.
//
// Packing:
//   state word 0 = [511:480]
//   key word 0   = [255:224]
//   nonce word 0 = [95:64]
//
// Encrypts 128 bits using the first four keystream words.
// Byte-order conversion remains the wrapper's responsibility.

module chacha20_core (
    input  wire         clk,
    input  wire         rst,
    input  wire         start,

    input  wire [127:0] data_in,
    input  wire [255:0] key,
    input  wire [95:0]  nonce,
    input  wire [31:0]  counter,

    output reg  [127:0] data_out,
    output reg          done
);

    localparam [1:0] ST_IDLE     = 2'd0;
    localparam [1:0] ST_COLUMN   = 2'd1;
    localparam [1:0] ST_DIAGONAL = 2'd2;
    localparam [1:0] ST_FINAL    = 2'd3;

    // ChaCha20 constants: "expand 32-byte k".
    localparam [31:0] C0 = 32'h61707865;
    localparam [31:0] C1 = 32'h3320646e;
    localparam [31:0] C2 = 32'h79622d32;
    localparam [31:0] C3 = 32'h6b206574;

    reg [1:0] state_ctrl;
    reg [1:0] qr_index;
    reg [3:0] double_round_count;

    reg [511:0] working_state;
    reg [511:0] working_next;
    reg [127:0] data_reg;

    wire [511:0] input_state;

    assign input_state = {
        C0, C1, C2, C3,
        key,
        counter,
        nonce
    };

    // Four banks, each containing four 32-bit words.
    wire [127:0] bank_a;
    wire [127:0] bank_b;
    wire [127:0] bank_c;
    wire [127:0] bank_d;

    assign bank_a = working_state[511:384];
    assign bank_b = working_state[383:256];
    assign bank_c = working_state[255:128];
    assign bank_d = working_state[127:0];

    wire use_diagonal;
    assign use_diagonal = (state_ctrl == ST_DIAGONAL);

    // Two-bit selectors wrap modulo 4.
    wire [1:0] sel_a;
    wire [1:0] sel_b;
    wire [1:0] sel_c;
    wire [1:0] sel_d;

    assign sel_a = qr_index;
    assign sel_b = qr_index + (use_diagonal ? 2'd1 : 2'd0);
    assign sel_c = qr_index + (use_diagonal ? 2'd2 : 2'd0);
    assign sel_d = qr_index + (use_diagonal ? 2'd3 : 2'd0);

    wire [31:0] qr_a;
    wire [31:0] qr_b;
    wire [31:0] qr_c;
    wire [31:0] qr_d;

    assign qr_a = bank_a[127 - 32*sel_a -: 32];
    assign qr_b = bank_b[127 - 32*sel_b -: 32];
    assign qr_c = bank_c[127 - 32*sel_c -: 32];
    assign qr_d = bank_d[127 - 32*sel_d -: 32];

    wire [31:0] qr_a_out;
    wire [31:0] qr_b_out;
    wire [31:0] qr_c_out;
    wire [31:0] qr_d_out;

    // One physical combinational quarter-round unit.
    chacha20_qr_iter1 qr_inst (
        .a     (qr_a),
        .b     (qr_b),
        .c     (qr_c),
        .d     (qr_d),
        .a_out (qr_a_out),
        .b_out (qr_b_out),
        .c_out (qr_c_out),
        .d_out (qr_d_out)
    );

    // Update the four selected words; preserve the others.
    integer i;

    always @* begin
        working_next = working_state;

        for (i = 0; i < 4; i = i + 1) begin
            if (sel_a == i[1:0])
                working_next[511 - 32*i -: 32] = qr_a_out;

            if (sel_b == i[1:0])
                working_next[383 - 32*i -: 32] = qr_b_out;

            if (sel_c == i[1:0])
                working_next[255 - 32*i -: 32] = qr_c_out;

            if (sel_d == i[1:0])
                working_next[127 - 32*i -: 32] = qr_d_out;
        end
    end

    // The first four initial-state words are always C0..C3.
    // No initial-state register is needed for this 128-bit output.
    // Each addition wraps modulo 2^32.
    wire [31:0] f0;
    wire [31:0] f1;
    wire [31:0] f2;
    wire [31:0] f3;
    wire [127:0] keystream_128;

    assign f0 = working_state[511:480] + C0;
    assign f1 = working_state[479:448] + C1;
    assign f2 = working_state[447:416] + C2;
    assign f3 = working_state[415:384] + C3;

    assign keystream_128 = {f0, f1, f2, f3};

    always @(posedge clk) begin
        if (rst) begin
            state_ctrl         <= ST_IDLE;
            qr_index           <= 2'd0;
            double_round_count <= 4'd0;
            working_state      <= 512'd0;
            data_reg           <= 128'd0;
            data_out           <= 128'd0;
            done               <= 1'b0;
        end else begin
            done <= 1'b0;

            case (state_ctrl)
                ST_IDLE: begin
                    if (start) begin
                        working_state      <= input_state;
                        data_reg           <= data_in;
                        qr_index           <= 2'd0;
                        double_round_count <= 4'd0;
                        state_ctrl         <= ST_COLUMN;
                    end
                end

                ST_COLUMN: begin
                    working_state <= working_next;

                    if (qr_index == 2'd3) begin
                        qr_index   <= 2'd0;
                        state_ctrl <= ST_DIAGONAL;
                    end else begin
                        qr_index <= qr_index + 2'd1;
                    end
                end

                ST_DIAGONAL: begin
                    working_state <= working_next;

                    if (qr_index == 2'd3) begin
                        qr_index <= 2'd0;

                        if (double_round_count == 4'd9) begin
                            state_ctrl <= ST_FINAL;
                        end else begin
                            double_round_count <=
                                double_round_count + 4'd1;
                            state_ctrl <= ST_COLUMN;
                        end
                    end else begin
                        qr_index <= qr_index + 2'd1;
                    end
                end

                ST_FINAL: begin
                    data_out   <= data_reg ^ keystream_128;
                    done       <= 1'b1;
                    state_ctrl <= ST_IDLE;
                end

                default: begin
                    state_ctrl         <= ST_IDLE;
                    qr_index           <= 2'd0;
                    double_round_count <= 4'd0;
                end
            endcase
        end
    end

endmodule


// Combinational ChaCha20 quarter-round.
module chacha20_qr_iter1 (
    input  wire [31:0] a,
    input  wire [31:0] b,
    input  wire [31:0] c,
    input  wire [31:0] d,

    output wire [31:0] a_out,
    output wire [31:0] b_out,
    output wire [31:0] c_out,
    output wire [31:0] d_out
);

    wire [31:0] a1, b1, c1, d1;
    wire [31:0] a2, b2, c2, d2;
    wire [31:0] dx1, bx1;
    wire [31:0] dx2, bx2;

    // a += b; d = ROTL(d XOR a, 16);
    assign a1  = a + b;
    assign dx1 = d ^ a1;
    assign d1  = {dx1[15:0], dx1[31:16]};

    // c += d; b = ROTL(b XOR c, 12);
    assign c1  = c + d1;
    assign bx1 = b ^ c1;
    assign b1  = {bx1[19:0], bx1[31:20]};

    // a += b; d = ROTL(d XOR a, 8);
    assign a2  = a1 + b1;
    assign dx2 = d1 ^ a2;
    assign d2  = {dx2[23:0], dx2[31:24]};

    // c += d; b = ROTL(b XOR c, 7);
    assign c2  = c1 + d2;
    assign bx2 = b1 ^ c2;
    assign b2  = {bx2[24:0], bx2[31:25]};

    assign a_out = a2;
    assign b_out = b2;
    assign c_out = c2;
    assign d_out = d2;

endmodule

`default_nettype wire