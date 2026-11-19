# 활성화 때 바꾼 LD_LIBRARY_PATH를 원래 값으로 되돌린다.
if [ -n "${_ZEEK_AD_OLD_LD_LIBRARY_PATH+x}" ]; then
    if [ -n "$_ZEEK_AD_OLD_LD_LIBRARY_PATH" ]; then
        export LD_LIBRARY_PATH="$_ZEEK_AD_OLD_LD_LIBRARY_PATH"
    else
        unset LD_LIBRARY_PATH
    fi
    unset _ZEEK_AD_OLD_LD_LIBRARY_PATH
fi
