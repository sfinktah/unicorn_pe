#pragma once
namespace _ {
    // copied from MSVC
    /*
    template <class _InIt, class _Ty, class _Fn>
    inline _Ty _Accumulate_unchecked(_InIt _First, _InIt _Last, _Ty _Val, _Fn& _Func)
    {  // return sum of _Val and all in [_First, _Last), using _Func
        for (; _First != _Last; ++_First) _Val = _Func(_Val, *_First);
        return (_Val);
    }
    */
}
