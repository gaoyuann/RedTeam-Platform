FROM alpine:3.19

# C/C++ 静态审计工具：cppcheck + flawfinder。gcc 为可用构建工具；当前源码流程不自动编译或执行被测代码。
RUN apk add --no-cache cppcheck gcc musl-dev python3 py3-pip make && \
    pip3 install --no-cache-dir --break-system-packages flawfinder
