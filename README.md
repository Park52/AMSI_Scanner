# AMSI_Scanner

해당 프로그램은 AMSI(Anti Malware Scan Interface)를 사용해서 파일의 악성 여부를 판단합니다.
AMSI에 대해서는 https://docs.microsoft.com/ko-kr/windows/win32/amsi/antimalware-scan-interface-portal#in-this-section 에서 확인할 수 있습니다.

해당 프로그램은 Visual Studio 2017에서 작성되었습니다.
EXE, DLL 형태 둘 다 제공하며 사용 예시는 아래와 같습니다.

### Usage

------

To Use this tool, simply provide the absolute file path you want to scan like this:

```shell
AMSI_Scanner.exe C:\Windows\System32\notepad.exe
```

