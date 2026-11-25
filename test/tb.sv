`timescale 1ns/1ps

module tb;
    parameter N = 64;

    reg clk = 0;
    always #5 clk = ~clk;

    reg rst_n = 0, ena = 1;
    reg [7:0] ui_in = 0, uio_in = 0;
    wire [7:0] uo_out, uio_out, uio_oe;

    tt_um_dinis_chacha20_V2 dut (.*);

    // Selector byte + 16 plaintext bytes.
    reg [135:0] frames [0:N-1];
    reg [127:0] expected [0:N-1];

    integer v, j, cycles;

    task tick;
        begin
            @(posedge clk);
            #1;
        end
    endtask

    task command(input [3:0] cmd, input [7:0] data);
        begin
            @(negedge clk);
            uio_in = {4'b0, cmd};
            ui_in = data;
            tick();
            @(negedge clk);
            uio_in = 0;
        end
    endtask

    task check(input condition, input [255:0] msg);
        begin
            if (condition !== 1'b1) begin
                $display("FAIL: %s", msg);
                $fatal(1);
            end
        end
    endtask

    task load_frame(input integer k);
        begin
            for (j = 0; j < 17; j = j + 1)
                command(1, frames[k][135-8*j -:8]);
            check(uio_out[5], "ready after 17 bytes");
        end
    endtask

    initial begin
        $readmemh("frames.hex", frames);
        $readmemh("expected.hex", expected);

        tick();
        tick();
        @(negedge clk);
        rst_n = 1;

        check(uio_oe == 8'hf0, "pin directions");

        command(2, 0);
        check(uio_out[7] && !uio_out[4], "reject premature start");
        command(8, 0);
        check(uio_out == 0, "abort clears status");

        command(3, 0);
        check(uio_out[7], "reject conflicting commands");
        command(8, 0);

        // Invalid selector must not advance the input count.
        command(1, 8'h08);
        check(uio_out[7] && !uio_out[5], "reject invalid selector");
        load_frame(0);
        check(uio_out[5], "invalid selector not counted");
        command(8, 0);

        for (v = 0; v < N; v = v + 1) begin
            load_frame(v);

            if (v == 0) begin
                command(1, 8'hff);
                check(uio_out[7] && uio_out[5], "reject extra byte");
                command(8, 0);
                load_frame(v);
            end

            command(2, 0);
            check(uio_out[4], "busy after start");

            if (v == 1) begin
                command(1, 8'hff);
                command(2, 0);
                check(uio_out[7], "busy command rejection");
            end

            cycles = 0;
            while (!uio_out[6] && cycles < 400) begin
                tick();
                cycles = cycles + 1;
            end
            check(uio_out[6] && !uio_out[4], "completion timeout");

            repeat (3) tick();

            for (j = 0; j < 16; j = j + 1) begin
                if (uo_out !== expected[v][127-8*j -:8]) begin
                    $display(
                        "vector %0d byte %0d got %02x expected %02x",
                        v, j, uo_out, expected[v][127-8*j -:8]
                    );
                    $fatal(1);
                end
                command(4, 0);
            end

            check(!uio_out[6] && uo_out == 0, "output drain");

            if (v == 1)
                command(8, 0);
            else
                check(!uio_out[7], "unexpected error");
        end

        // Reset during computation.
        load_frame(0);
        command(2, 0);
        repeat (8) tick();

        @(negedge clk);
        rst_n = 0;
        tick();
        @(negedge clk);
        rst_n = 1;

        repeat (400) tick();
        check(uio_out == 0, "reset abort");

        // Deselect during computation.
        load_frame(0);
        command(2, 0);
        @(negedge clk);
        ena = 0;
        tick();
        check(uio_oe == 0 && uo_out == 0, "deselected outputs");

        @(negedge clk);
        ena = 1;
        repeat (400) tick();
        check(uio_out == 0, "deselect abort");

        // Verify a complete transaction after the abort.
        load_frame(0);
        command(2, 0);
        repeat (400) tick();
        check(uio_out[6], "restart after abort");

        for (j = 0; j < 16; j = j + 1) begin
            check(
                uo_out == expected[0][127-8*j -:8],
                "result after abort"
            );
            command(4, 0);
        end

        $display(
            "PASS: %0d vectors, all 8 keys, protocol errors, reset and deselection",
            N
        );
        $finish;
    end

    initial begin
        #1000000;
        $fatal(1, "watchdog timeout");
    end
endmodule