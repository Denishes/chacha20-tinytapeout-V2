`timescale 1ns/1ps
module tb;
reg clk, rst_n, ena;
reg [7:0] ui_in, uio_in;
wire [7:0] uo_out, uio_out, uio_oe;
`ifdef GL_TEST
supply1 VPWR;
supply0 VGND;
`endif
tt_um_dinis_chacha20_V2 dut (
`ifdef GL_TEST
 .VPWR(VPWR), .VGND(VGND),
`endif
 .clk(clk),.rst_n(rst_n),.ena(ena),.ui_in(ui_in),.uio_in(uio_in),
 .uo_out(uo_out),.uio_out(uio_out),.uio_oe(uio_oe));
endmodule
