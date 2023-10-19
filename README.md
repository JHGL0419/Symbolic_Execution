# Symbolic_Execution

## Tools
### PE 파일 분석
- PEview
- CFF Explorer (이거 주로 사용)
  - https://github.com/cybertechniques/site/blob/master/analysis_tools/cff-explorer/index.md
  - pe파일 수정도 가능해서 좋음. ex) aslr 끄기.
- Aslr이 위 방법으로도 안꺼지면 https://m.blog.naver.com/techshare/221507922086 (.net의 경우 이 방법으로 해야 하나봄)

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
  - else 빼먹어서 2입력하면 success fail 둘다 떠버림.

## Angr test code
- angr_test.py
  - main test code
- parsing.py
  - regs.txt, mem.txt를 parsing하는 모듈.
  - regs.txt, mem.txt는 state바꿀 때마다 수정해주세요.

## DMP(windows dump file) 분석
- DMP파일 얻는 법.
  1. 디버거나 파일 실행시키고 원하는 부분까지 실행
  2. 작업관리자 들어가서 원하는 파일 선택 후 오른쪽 클릭
    - 디버거로 실행했을 때는 두개 뜰 수가 있는데 오른쪽 클릭 -> 속성 시 실행 파일과 같은 것
  3. 덤프파일 만들기 클릭
- minidump
  - https://github.com/skelsec/minidump
  - 약간 수정한 부분이 있어서 original 파일 말고 여기 올려놓은 거로 써주세요.
  - minidump 디렉토리로 가서 python(3) ./setup.py install
  - 실행할 때 minidump.py안되면 minidump로 해보세요. (나는 전자 안됨.)
  - parsing.py에다 memory복사하는 method 만들어놓았음. 구리긴하지만...
    - `parse_dump(filename, seg_addr, seg_size, state)`
