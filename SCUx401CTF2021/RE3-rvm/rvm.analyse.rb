class RVM
    def initialize(shellcode)
        @PC = 0
        @FLAG = 1
        @shellcode = shellcode
        @reg = Array.new(27, 0)
    end

    def run
        begin 
            op = @shellcode[@PC]
            #ADD reg, imm
            op == "1" ? (puts "@reg[#{@shellcode[(@PC + 1)..(@PC + 2)].to_i}] += #{@shellcode[(@PC + 3)..(@PC + 4)].to_i}";@PC += 5) :
            #XOR reg, imm
            op == "2" ? (puts "@reg[#{@shellcode[(@PC + 1)..(@PC + 2)].to_i}] ^= #{@shellcode[(@PC + 3)..(@PC + 4)].to_i}";@PC += 5) :  
            #SUB reg, imm
            op == "3" ? (puts "@reg[#{@shellcode[(@PC + 1)..(@PC + 2)].to_i}] -= #{@shellcode[(@PC + 3)..(@PC + 4)].to_i}";@PC += 5) :  
            #WRITE imm.chr
            op == "4" ? (puts "STDOUT<<#{@shellcode[(@PC + 1)..(@PC + 3)].to_i.chr}";@PC += 4) :  
            #CMP
            op == "5" ? (puts "((@reg[#{@shellcode[(@PC + 1)..(@PC + 2)].to_i}] == #{@shellcode[(@PC + 3)..(@PC + 5)].to_i}) ? @FLAG &= 1 : @FLAG = 0)";@PC += 6) :
            #READ reg 
            op == "6" ? (puts "READ reg";@PC += 1) : 
            #JNZ 1
            op == "7" ? (puts "JNZ 1";@PC += 2) : ()
        end while @PC < @shellcode.length
    end

    def printreg
        puts @reg.inspect
    end

    def printflag
        puts @FLAG
    end

end

#scuctf{ruby_1s_y0ur_fr13nd}
rvm = RVM.new "40734110411241174116405861000110102102031030410405105061060710708108091091011011111121121311314114151151611617117181181911920120211212212223123241242512526126272004120161202762033420458205142060520798208392098421064211632126921314214522158621613217782187521987220802216522279223692247622502226765000935010885020525030695040675050985061355070245080895090565101965110845121235131435140905152235160765172015182065190365200435212015220075230145242035251245262127840794075"
rvm.run