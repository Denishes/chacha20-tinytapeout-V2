`default_nettype none

// ChaCha20: two complete quarter-round units.
//
// 20 rounds x 4 quarter-rounds / 2 units = 40 processing cycles.
// Final feed-forward and plaintext XOR = 1 additional cycle.
//
// Latency: 41 cycles from accepted start to done.
// Minimum initiation interval: 42 cycles.
//
// Inputs are captured when start is accepted in ST_IDLE.
// start is ignored while processing.
// done is asserted for one cycle.
// data_out holds its value until the next result or reset.
//
// Synchronous active-high reset aborts the current operation.
//
// Packing:
//   state word 0 = [511:480]
//   key word 0   = [255:224]
//   nonce word 0 = [95:64]
//
// Encrypts 128 bits using the first four ChaCha20 keystream words.

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

    // 0: process quarter-round indices 0 and 1.
    // 1: process quarter-round indices 2 and 3.
    reg qr_pair;

    // Counts ten column/diagonal pairs: 0 through 9.
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
    //
    // bank_a: s0,  s1,  s2,  s3
    // bank_b: s4,  s5,  s6,  s7
    // bank_c: s8,  s9,  s10, s11
    // bank_d: s12, s13, s14, s15

    wire [127:0] bank_a = working_state[511:384];
    wire [127:0] bank_b = working_state[383:256];
    wire [127:0] bank_c = working_state[255:128];
    wire [127:0] bank_d = working_state[127:0];

    wire use_diagonal = (state_ctrl == ST_DIAGONAL);

    // Selectors for each physical quarter-round unit.
    wire [1:0] sel_a [0:1];
    wire [1:0] sel_b [0:1];
    wire [1:0] sel_c [0:1];
    wire [1:0] sel_d [0:1];

    // Results from the two quarter-round units.
    wire [31:0] qa [0:1];
    wire [31:0] qb [0:1];
    wire [31:0] qc [0:1];
    wire [31:0] qd [0:1];

    genvar g;
    generate
        for (g = 0; g < 2; g = g + 1) begin : QR_UNITS

            // g is a generate-time constant: 0 or 1.
            // Concatenation produces an exact two-bit selector.
            assign sel_a[g] = {qr_pair, g[0]};

            // Two-bit additions wrap modulo 4.
            assign sel_b[g] =
                sel_a[g] + (use_diagonal ? 2'd1 : 2'd0);

            assign sel_c[g] =
                sel_a[g] + (use_diagonal ? 2'd2 : 2'd0);

            assign sel_d[g] =
                sel_a[g] + (use_diagonal ? 2'd3 : 2'd0);

            chacha20_qr_iter2 qr_inst (
                .a(bank_a[127-32*sel_a[g] -: 32]),
                .b(bank_b[127-32*sel_b[g] -: 32]),
                .c(bank_c[127-32*sel_c[g] -: 32]),
                .d(bank_d[127-32*sel_d[g] -: 32]),

                .a_out(qa[g]),
                .b_out(qb[g]),
                .c_out(qc[g]),
                .d_out(qd[g])
            );

        end
    endgenerate

    // Each cycle updates eight words and preserves the other eight.
    // The two quarter-round units operate on disjoint words.
    integer i;

    always @* begin
        working_next = working_state;

        for (i = 0; i < 4; i = i + 1) begin

            if (sel_a[0] == i[1:0])
                working_next[511-32*i -: 32] = qa[0];
            else if (sel_a[1] == i[1:0])
                working_next[511-32*i -: 32] = qa[1];

            if (sel_b[0] == i[1:0])
                working_next[383-32*i -: 32] = qb[0];
            else if (sel_b[1] == i[1:0])
                working_next[383-32*i -: 32] = qb[1];

            if (sel_c[0] == i[1:0])
                working_next[255-32*i -: 32] = qc[0];
            else if (sel_c[1] == i[1:0])
                working_next[255-32*i -: 32] = qc[1];

            if (sel_d[0] == i[1:0])
                working_next[127-32*i -: 32] = qd[0];
            else if (sel_d[1] == i[1:0])
                working_next[127-32*i -: 32] = qd[1];

        end
    end

    // Only the first four feed-forward words are needed.
    // Their original values are always C0, C1, C2 and C3.
    // Each addition is modulo 2^32.
    wire [31:0] f0 = working_state[511:480] + C0;
    wire [31:0] f1 = working_state[479:448] + C1;
    wire [31:0] f2 = working_state[447:416] + C2;
    wire [31:0] f3 = working_state[415:384] + C3;

    wire [127:0] keystream_128 = {f0, f1, f2, f3};

    always @(posedge clk) begin
        if (rst) begin
            state_ctrl         <= ST_IDLE;
            qr_pair            <= 1'b0;
            double_round_count <= 4'd0;

            working_state      <= 512'd0;
            data_reg           <= 128'd0;

            data_out           <= 128'd0;
            done               <= 1'b0;

        end else begin
            // Default: done is a one-cycle pulse.
            done <= 1'b0;

            case (state_ctrl)

                ST_IDLE: begin
                    if (start) begin
                        working_state      <= input_state;
                        data_reg           <= data_in;

                        qr_pair            <= 1'b0;
                        double_round_count <= 4'd0;

                        state_ctrl         <= ST_COLUMN;
                    end
                end

                ST_COLUMN: begin
                    // Commit two complete column quarter-rounds.
                    working_state <= working_next;

                    if (!qr_pair) begin
                        // Next cycle processes indices 2 and 3.
                        qr_pair <= 1'b1;
                    end else begin
                        // All four column quarter-rounds completed.
                        qr_pair    <= 1'b0;
                        state_ctrl <= ST_DIAGONAL;
                    end
                end

                ST_DIAGONAL: begin
                    // Commit two complete diagonal quarter-rounds.
                    working_state <= working_next;

                    if (!qr_pair) begin
                        // Next cycle processes indices 2 and 3.
                        qr_pair <= 1'b1;
                    end else begin
                        // One complete double-round has finished.
                        qr_pair <= 1'b0;

                        if (double_round_count == 4'd9) begin
                            // Ten double-rounds = twenty rounds.
                            state_ctrl <= ST_FINAL;
                        end else begin
                            double_round_count <=
                                double_round_count + 4'd1;

                            state_ctrl <= ST_COLUMN;
                        end
                    end
                end

                ST_FINAL: begin
                    // working_state contains all twenty rounds.
                    data_out <= data_reg ^ keystream_128;
                    done     <= 1'b1;

                    state_ctrl <= ST_IDLE;
                end

                default: begin
                    state_ctrl         <= ST_IDLE;
                    qr_pair            <= 1'b0;
                    double_round_count <= 4'd0;
                end

            endcase
        end
    end

endmodule


// Complete combinational ChaCha20 quarter-round.
// Each addition wraps modulo 2^32.
// Rotations are implemented as fixed wiring.

module chacha20_qr_iter2 (
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

    // a += b; d ^= a; d = ROTL(d, 16);
    assign a1  = a + b;
    assign dx1 = d ^ a1;
    assign d1  = {dx1[15:0], dx1[31:16]};

    // c += d; b ^= c; b = ROTL(b, 12);
    assign c1  = c + d1;
    assign bx1 = b ^ c1;
    assign b1  = {bx1[19:0], bx1[31:20]};

    // a += b; d ^= a; d = ROTL(d, 8);
    assign a2  = a1 + b1;
    assign dx2 = d1 ^ a2;
    assign d2  = {dx2[23:0], dx2[31:24]};

    // c += d; b ^= c; b = ROTL(b, 7);
    assign c2  = c1 + d2;
    assign bx2 = b1 ^ c2;
    assign b2  = {bx2[24:0], bx2[31:25]};

    assign a_out = a2;
    assign b_out = b2;
    assign c_out = c2;
    assign d_out = d2;

endmodule

`default_nettype wire