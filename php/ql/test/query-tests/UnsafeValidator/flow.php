<?php
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
class C {
  function a(Request $request) {
    Validator::make($request->all(), [
      "code" => [ Rule::unique("t")->ignore($request->input('id')), "required" ],  // WANT line 7 (request->input)
      "name" => [ Rule::unique("t")->ignore($request->chart_id), "required" ],     // WANT line 8 (request property)
    ]);
  }
  function b(Request $request) {
    $x = Rule::exists('users')->ignore($request->uid);  // WANT line 12 (exists + property)
    $safe = Rule::unique('users')->ignore(42);          // must NOT flow (line 13 literal)
    return [$x, $safe];
  }
}
