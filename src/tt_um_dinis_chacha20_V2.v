`default_nettype none

module tt_um_dinis_chacha20_V2 (
    input  wire [7:0] ui_in,
    output wire [7:0] uo_out,
    input  wire [7:0] uio_in,
    output wire [7:0] uio_out,
    output wire [7:0] uio_oe,
    input  wire       ena,
    input  wire       clk,
    input  wire       rst_n
);

    reg [127:0] frame;
    reg [2:0] key_sel;
    reg [4:0] count;
    reg [3:0] out_index;
    reg busy, valid, error, start;

    wire abort_cmd = uio_in[3];
    wire reset = !rst_n || !ena || abort_cmd;

    localparam [95:0] NONCE = 96'h000000000000004A00000000;
    localparam [31:0] COUNTER = 32'h00000001;

    // Same packed key constants as the FPGA top.v.
    function [255:0] key_lookup;
        input [2:0] sel;
        begin
            case (sel)
                3'd0: key_lookup =
                    256'h000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F;
                3'd1: key_lookup =
                    256'h202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F;
                3'd2: key_lookup =
                    256'h404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F;
                3'd3: key_lookup =
                    256'h606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F;
                3'd4: key_lookup =
                    256'h808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F;
                3'd5: key_lookup =
                    256'hA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF;
                3'd6: key_lookup =
                    256'hC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF;
                3'd7: key_lookup =
                    256'hE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF;
                default: key_lookup = 256'b0;
            endcase
        end
    endfunction

    function [31:0] le_word;
        input [31:0] x;
        begin
            le_word = {x[7:0], x[15:8], x[23:16], x[31:24]};
        end
    endfunction

    wire [255:0] key = key_lookup(key_sel);
    wire [127:0] plaintext;
    wire [127:0] ciphertext;
    wire done;

    // Preserve the Tiny Tapeout plaintext byte ordering.
    genvar i;
    generate
        for (i = 0; i < 4; i = i + 1) begin : data_words
            assign plaintext[127-32*i -:32] =
                le_word(frame[127-32*i -:32]);
        end
    endgenerate

    chacha20_core core (
        .clk      (clk),
        .rst      (reset),
        .start    (start),
        .key      (key),
        .nonce    (NONCE),
        .counter  (COUNTER),
        .data_in  (plaintext),
        .data_out (ciphertext),
        .done     (done)
    );

    // Output bytes in little-endian order within each core word.
    wire [6:0] output_bit =
        7'd96 - {out_index[3:2], 5'b0}
              + {2'b0, out_index[1:0], 3'b0};

    assign uo_out = (ena && valid)
                  ? ciphertext[output_bit +:8]
                  : 8'b0;

    // Inputs:  uio[0]=load, [1]=start, [2]=next, [3]=abort.
    // Outputs: uio[4]=busy, [5]=ready, [6]=valid, [7]=error.
    assign uio_out = {
        error,
        valid,
        (!busy && count == 5'd17),
        busy,
        4'b0
    };

    assign uio_oe = ena ? 8'hf0 : 8'h00;

    wire _unused = &{1'b0, uio_in[7:4]};

    always @(posedge clk) begin
        if (reset) begin
            frame     <= 0;
            key_sel   <= 0;
            count     <= 0;
            out_index <= 0;
            busy      <= 0;
            valid     <= 0;
            error     <= 0;
            start     <= 0;
        end else begin
            start <= 0;

            if (done && busy) begin
                busy      <= 0;
                valid     <= 1;
                out_index <= 0;
            end

            case (uio_in[2:0])
                3'b000: begin
                    // Idle.
                end

                3'b001: begin
                    if (!busy && count < 5'd17) begin
                        if (count == 0) begin
                            // First byte selects key 0 through 7.
                            // Reject other values without advancing.
                            if (ui_in[7:3] == 5'b0) begin
                                key_sel <= ui_in[2:0];
                                count   <= 5'd1;
                            end else begin
                                error <= 1;
                            end
                        end else begin
                            // Remaining 16 bytes are plaintext.
                            frame <= {frame[119:0], ui_in};
                            count <= count + 1'b1;
                        end
                    end else begin
                        error <= 1;
                    end
                end

                3'b010: begin
                    if (!busy && count == 5'd17) begin
                        start     <= 1;
                        busy      <= 1;
                        valid     <= 0;
                        count     <= 0;
                        out_index <= 0;
                    end else begin
                        error <= 1;
                    end
                end

                3'b100: begin
                    // Sample the current byte BEFORE this clock edge.
                    if (valid) begin
                        if (out_index == 4'd15) begin
                            valid     <= 0;
                            out_index <= 0;
                        end else begin
                            out_index <= out_index + 1'b1;
                        end
                    end else begin
                        error <= 1;
                    end
                end

                default: begin
                    // Conflicting commands.
                    error <= 1;
                end
            endcase
        end
    end

endmodule

`default_nettype wire