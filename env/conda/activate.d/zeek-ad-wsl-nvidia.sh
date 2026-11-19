# WSL 전용: Windows 드라이버가 제공하는 NVIDIA 라이브러리를 먼저 찾게 한다.
# Ubuntu의 nvidia-cuda-toolkit이 Linux용 드라이버 라이브러리(libnvidia-compute-580 등)를
# /lib/x86_64-linux-gnu에 설치해 두었다. WSL의 libcuda가 그 버전의 ptxjitcompiler를 읽으면
# torch.cuda.is_available()에서 Segmentation fault가 난다.
# 드라이버 폴더 이름은 Windows 드라이버를 업데이트하면 바뀌므로 활성화할 때마다 찾는다.
_zeek_ad_nv_lib=$(ls /usr/lib/wsl/drivers/*/libnvidia-ptxjitcompiler.so.1 2>/dev/null | head -n 1)
if [ -n "$_zeek_ad_nv_lib" ]; then
    export _ZEEK_AD_OLD_LD_LIBRARY_PATH="${LD_LIBRARY_PATH-}"
    export LD_LIBRARY_PATH="$(dirname "$_zeek_ad_nv_lib")${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi
unset _zeek_ad_nv_lib
