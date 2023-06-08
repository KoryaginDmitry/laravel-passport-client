<?php

namespace App\Http\Controllers;

use App\Helpers\Passport\Passport;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\View\Factory;
use Illuminate\Contracts\View\View;

class ProfileController extends Controller
{
    /**
     * Страница с данными авторизованного пользователя
     * @return Application|Factory|View
     */
    public function profile(): View|Factory|Application
    {
        return view('profile', [
            'user' => Passport::authUser()
        ]);
    }
}
