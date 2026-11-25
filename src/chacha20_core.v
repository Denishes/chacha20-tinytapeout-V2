`default_nettype none

// Iterative ChaCha20 with four complete quarter-round units.
//
// One column round per cycle.
// One diagonal round per cycle.
// Ten double-rounds = 20 processing cycles.
// Final feed-forward and plaintext XOR = 1 additional cycle.
//
// Latency: 21 cycles from accepted start to done.
// Minimum initiation interval: 22 cycles.
//
// start is accepted only in ST_IDLE.
// Inputs are captured when the request is accepted.
// start is ignored while processing.
//
// done pulses for one cycle when data_out becomes valid.
// data_out holds its value until another result or reset.
//
// Synchronous active-high reset aborts the current operation.
//
// Packing:
//   state word 0 = [511:480]
//   key word 0   = [255:224]
//   nonce word 0 = [95:64]
//
// Encrypts 128 bits using the first four keystream words.
//
// All helper logic is included in this file.

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
    reg [3:0] double_round_count;

    reg [511:0] working_state;
    reg [127:0] data_reg;

    wire [511:0] input_state = {
        C0, C1, C2, C3,
        key,
        counter,
        nonce
    };

    // Unpack the sixteen numerical 32-bit state words.
    wire [31:0] s0  = working_state[511:480];
    wire [31:0] s1  = working_state[479:448];
    wire [31:0] s2  = working_state[447:416];
    wire [31:0] s3  = working_state[415:384];

    wire [31:0] s4  = working_state[383:352];
    wire [31:0] s5  = working_state[351:320];
    wire [31:0] s6  = working_state[319:288];
    wire [31:0] s7  = working_state[287:256];

    wire [31:0] s8  = working_state[255:224];
    wire [31:0] s9  = working_state[223:192];
    wire [31:0] s10 = working_state[191:160];
    wire [31:0] s11 = working_state[159:128];

    wire [31:0] s12 = working_state[127:96];
    wire [31:0] s13 = working_state[95:64];
    wire [31:0] s14 = working_state[63:32];
    wire [31:0] s15 = working_state[31:0];

    wire use_diagonal = (state_ctrl == ST_DIAGONAL);

    wire [31:0] q0a, q0b, q0c, q0d;
    wire [31:0] q1a, q1b, q1c, q1d;
    wire [31:0] q2a, q2b, q2c, q2d;
    wire [31:0] q3a, q3b, q3c, q3d;

    // Four physical quarter-round units.
    // The same units are reused for columns and diagonals.

    // Column:   QR(0, 4, 8, 12)
    // Diagonal: QR(0, 5, 10, 15)
    chacha20_qr_iter4 qr0 (
        .a(s0),
        .b(use_diagonal ? s5  : s4),
        .c(use_diagonal ? s10 : s8),
        .d(use_diagonal ? s15 : s12),

        .a_out(q0a),
        .b_out(q0b),
        .c_out(q0c),
        .d_out(q0d)
    );

    // Column:   QR(1, 5, 9, 13)
    // Diagonal: QR(1, 6, 11, 12)
    chacha20_qr_iter4 qr1 (
        .a(s1),
        .b(use_diagonal ? s6  : s5),
        .c(use_diagonal ? s11 : s9),
        .d(use_diagonal ? s12 : s13),

        .a_out(q1a),
        .b_out(q1b),
        .c_out(q1c),
        .d_out(q1d)
    );

    // Column:   QR(2, 6, 10, 14)
    // Diagonal: QR(2, 7, 8, 13)
    chacha20_qr_iter4 qr2 (
        .a(s2),
        .b(use_diagonal ? s7  : s6),
        .c(use_diagonal ? s8  : s10),
        .d(use_diagonal ? s13 : s14),

        .a_out(q2a),
        .b_out(q2b),
        .c_out(q2c),
        .d_out(q2d)
    );

    // Column:   QR(3, 7, 11, 15)
    // Diagonal: QR(3, 4, 9, 14)
    chacha20_qr_iter4 qr3 (
        .a(s3),
        .b(use_diagonal ? s4  : s7),
        .c(use_diagonal ? s9  : s11),
        .d(use_diagonal ? s14 : s15),

        .a_out(q3a),
        .b_out(q3b),
        .c_out(q3c),
        .d_out(q3d)
    );

    // Restore the original state-word order after a column round.
    wire [511:0] column_result = {
        q0a, q1a, q2a, q3a,
        q0b, q1b, q2b, q3b,
        q0c, q1c, q2c, q3c,
        q0d, q1d, q2d, q3d
    };

    // Restore the original state-word order after a diagonal round.
    wire [511:0] diagonal_result = {
        q0a, q1a, q2a, q3a,
        q3b, q0b, q1b, q2b,
        q2c, q3c, q0c, q1c,
        q1d, q2d, q3d, q0d
    };

    // Feed-forward for the first four output words.
    // Their initial values are always the ChaCha20 constants.
    // All additions are modulo 2^32.
    wire [31:0] f0 = working_state[511:480] + C0;
    wire [31:0] f1 = working_state[479:448] + C1;
    wire [31:0] f2 = working_state[447:416] + C2;
    wire [31:0] f3 = working_state[415:384] + C3;

    wire [127:0] keystream_128 = {f0, f1, f2, f3};

    always @(posedge clk) begin
        if (rst) begin
            state_ctrl         <= ST_IDLE;
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

                        double_round_count <= 4'd0;
                        state_ctrl         <= ST_COLUMN;
                    end
                end

                ST_COLUMN: begin
                    // Four column quarter-rounds complete together.
                    working_state <= column_result;
                    state_ctrl    <= ST_DIAGONAL;
                end

                ST_DIAGONAL: begin
                    // Four diagonal quarter-rounds complete together.
                    working_state <= diagonal_result;

                    if (double_round_count == 4'd9) begin
                        // Ten double-rounds = twenty rounds.
                        state_ctrl <= ST_FINAL;
                    end else begin
                        double_round_count <=
                            double_round_count + 4'd1;

                        state_ctrl <= ST_COLUMN;
                    end
                end

                ST_FINAL: begin
                    // State already includes all twenty rounds.
                    data_out <= data_reg ^ keystream_128;
                    done     <= 1'b1;

                    state_ctrl <= ST_IDLE;
                end

                default: begin
                    state_ctrl         <= ST_IDLE;
                    double_round_count <= 4'd0;
                end

            endcase
        end
    end

endmodule


// Complete combinational ChaCha20 quarter-round.
// Instantiated four times by chacha20_core.

module chacha20_qr_iter4 (
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