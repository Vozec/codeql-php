<?php
// Laravel file-write sinks: a user-controlled upload destination name is arbitrary file write
// (path traversal / webshell); a constant destination name is not.
use Illuminate\Http\Request;

function upload(Request $request) {
    $name = $request->input('name');
    return $request->file('doc')->storeAs('uploads', $name);        // BUG: user-controlled destination name
}

function safe_upload(Request $request) {
    return $request->file('doc')->storeAs('uploads', 'fixed.pdf');  // safe: constant name, no taint
}
