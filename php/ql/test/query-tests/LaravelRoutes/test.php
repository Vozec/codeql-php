<?php
Route::get('/users', [UserController::class, 'index']);
Route::post('/users', 'UserController@store');
Route::get('/profile', function () { return view('profile'); });
Route::put('/users/{id}', [UserController::class, 'update']);
Route::delete('/users/{id}', 'UserController@destroy');
Route::resource('photos', PhotoController::class);
Route::match(['get', 'post'], '/search', 'SearchController@index');
$router->get('/api/ping', 'ApiController@ping');
$obj->getData();          // not a route (verb 'get'? no -> 'getData' not a verb)
