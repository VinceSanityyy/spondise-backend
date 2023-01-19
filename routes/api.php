<?php

use App\Http\Controllers\API\AuthenticationController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\API\VerifyEmailController;
// use Illuminate\Foundation\Auth\EmailVerificationRequest;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});


Route::post('login', [AuthenticationController::class, 'login']);
Route::post('register', [AuthenticationController::class, 'register']);
Route::post('logout', [AuthenticationController::class, 'logout']);
Route::get('auth/gmail/callback', [AuthenticationController::class, 'googleLogin']);
Route::get('/login/{provider}', [AuthenticationController::class,'redirectToGoogle']);

Route::middleware('auth:sanctum')->group(function(){
    Route::get('me',[AuthenticationController::class,'getCurrentUser']);
});

// Route::get('/email/verify/{id}/{hash}', function (VerifyEmailController $request) {
//     $request->fulfill();
// })->middleware(['auth:sanctum', 'signed'])->name('verification.verify');

Route::get('/email/verify/{id}/{hash}', [VerifyEmailController::class, '__invoke'])
    ->middleware(['signed', 'throttle:6,1'])
    ->name('verification.verify');


Route::get('/login',function(){
    // dd('verified');
})->name('login');