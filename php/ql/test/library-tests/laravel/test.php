<?php
// Taint flowing THROUGH Laravel core APIs (no vendor/ extracted).
class C1 {
  public function a(Request $request) {
    $id = $request->input('id');
    DB::statement("SELECT * FROM users WHERE id = " . $id);      // BUG: SQLi via Request->input + DB::statement
  }
  public function b(Request $request) {
    DB::table('u')->whereRaw("name = '" . request('name') . "'"); // BUG: request() helper + whereRaw
  }
  public function c(Request $request) {
    $u = Str::upper($request->input('x'));
    DB::statement($u);                                            // BUG: taint through Str::upper step
  }
  public function d(Request $request) {
    return redirect($request->input('url'));                      // BUG: open redirect
  }
  public function safe1(Request $request) {
    DB::statement("SELECT 1");                                    // ok: constant
  }
  public function safe2(Request $request) {
    $clean = intval($request->input('id'));
    DB::statement("SELECT * FROM u WHERE id=" . $clean);          // ok: intval sanitizer
  }
}
