/**
* Date: October 7, 2013
* Authors: Talha Zekeriya Durmuş, talhazekeriyadurmus@gmail.com
* License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).
* Copyright: Rhodeus 2013
*/

module rhodeus.c;
import core.stdc.string: strlen;

auto cstr2dstr(inout(char)* cstr){
    return cast(string) (cstr ? cstr[0 .. strlen(cstr)] : "");
}
auto cstr2dstr(char[] cstr){
    return cast(string) (cstr ? cstr[0 .. strlen(cstr.ptr)] : "");
}