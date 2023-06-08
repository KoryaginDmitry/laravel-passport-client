<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\HomeController;
use App\Http\Controllers\ProfileController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::middleware('passportAuth')->group(static function () {
    Route::get('logout', [AuthController::class, 'logout'])->name('logout');

    Route::get('profile', [ProfileController::class, 'profile'])->name('profile');
});

Route::middleware('passportGuest')->group(static function () {
    Route::controller(AuthController::class)->group(static function () {
        Route::get('/redirect', 'redirect')->name('auth');
        Route::get('auth/callback', 'callback');
    });
});

Route::get('/', [HomeController::class, 'home'])->name('home');
