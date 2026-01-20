@echo off
setlocal

echo.
echo ============================================
echo   v3 Client Build (Windows Single Edition)
echo ============================================
echo.

set CC=gcc
set CFLAGS=-Wall -Wextra -O2 -I include
set LDFLAGS=-lws2_32 -lmswsock -ladvapi32
set OUT=v3_client.exe

set SRCS=src/v3_main.c src/v3_utils.c src/v3_crypto.c src/v3_session.c src/v3_socks5.c

echo [BUILD] Compiling...
%CC% %CFLAGS% -o %OUT% %SRCS% %LDFLAGS%

if errorlevel 1 (
    echo [ERROR] Build failed!
    exit /b 1
)

echo [OK] Built: %OUT%
echo.

:: 可选: 运行测试
if "%1"=="test" (
    echo [TEST] Running with test server...
    %OUT% -s 127.0.0.1 -p 51820 -l 10808 -v
)

endlocal
