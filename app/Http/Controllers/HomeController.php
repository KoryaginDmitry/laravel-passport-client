<?php

namespace App\Http\Controllers;

use App\Helpers\Passport\Passport;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\View\Factory;
use Illuminate\Contracts\View\View;

class HomeController extends Controller
{
    /**
     * Страница для неавторизованного пользователя
     * @return Application|Factory|View
     */
    public function home(): View|Factory|Application
    {
        return view('main', [
            'user' => Passport::authUser(),
        ]);
    }
}
