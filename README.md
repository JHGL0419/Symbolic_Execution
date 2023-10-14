# Symbolic_Execution

## Tools
### PE 파일 분석
- PEview
- CFF Explorer (이거 주로 사용)
  - https://github.com/cybertechniques/site/blob/master/analysis_tools/cff-explorer/index.md
  - pe파일 수정도 가능해서 좋음. ex) aslr 끄기.

### Debugger
- x96dbg(x32dbg + x64dbg)
  - https://github.com/x64dbg/x64dbg
  - 각 파일에 맞는 비트로 열면 됨.
  - register 창에서 그냥 오른쪽 커서 클릭 -> all register copy 가능
  - memory도 범위가 넓으면 귀찮긴 하지만 드래그 해서 copy 가능
  - 다른 디버거들이랑 단축키 비슷. 

## Binary file(/bin)
exe파일 aslr을 꺼뒀고, dll들은 aslr끄려면 권한 수정해야되는데 좀 무서워서 일단 그냥 함.
- ctype.exe 2입력시 success. 아니면 fail.
  - else 빼먹어서 2입력하면 success fail 둘다 뜨는데 고치기 귀차나...

## Angr test code
- angr_test.py
  - main test code
- parsing.py
  - regs.txt, mem.txt parsing하는 모듈.
  - regs.txt, mem.txt는 state바꿀 때마다 수정해주세요.

## DMP(windows dump file) 분석
- minidump
  - 약간 수정해서 original 파일 말고 이걸로 써주세요.
  - minidump 디렉토리로 가서 python(3) ./setup.py install
    - virtualenv 환경에서 하니까 minidump 커맨드가 안되던데 설치하고 virtualenv 환경에서 `minidump -r [addr] -s [read_size] [file_name]` 하시길...