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
            op == "1" ? (@reg[@shellcode[(@PC + 1)..(@PC + 2)].to_i] += @shellcode[(@PC + 3)..(@PC + 4)].to_i;@PC += 5) :
            op == "2" ? (@reg[@shellcode[(@PC + 1)..(@PC + 2)].to_i] ^= @shellcode[(@PC + 3)..(@PC + 4)].to_i;@PC += 5) :
            op == "3" ? (@reg[@shellcode[(@PC + 1)..(@PC + 2)].to_i] -= @shellcode[(@PC + 3)..(@PC + 4)].to_i;@PC += 5) :
            op == "4" ? (STDOUT<<@shellcode[(@PC + 1)..(@PC + 3)].to_i.chr;@PC += 4) :
            op == "5" ? (((@reg[@shellcode[(@PC + 1)..(@PC + 2)].to_i] == @shellcode[(@PC + 3)..(@PC + 5)].to_i) ? @FLAG &= 1 : @FLAG = 0);@PC += 6) :
            op == "6" ? (input = gets.chomp;input.length == 27 ? 27.times{|i| @reg[i] = input[i][0].ord} : (puts "ciscnnb";break);@PC += 1) :
            op == "7" ? (@PC += @FLAG == 1 ? 2 : 1) : (puts "360nb";break)
        end while @PC < @shellcode.length
    end

end

rvm = RVM.new "40734110411241174116405861000110102102031030410405105061060710708108091091011011111121121311314114151151611617117181181911920120211212212223123241242512526126272004120161202762033420458205142060520798208392098421064211632126921314214522158621613217782187521987220802216522279223692247622502226765000935010885020525030695040675050985061355070245080895090565101965110845121235131435140905152235160765172015182065190365200435212015220075230145242035251245262127840794075"
rvm.run