<?php

namespace App\Http\Middleware;

use App\Helpers\Passport\Passport;
use Closure;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

class AuthPassportMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param Request $request
     * @param Closure(Request): (Response|RedirectResponse) $next
     * @return Response|RedirectResponse
     */
    public function handle(Request $request, Closure $next): Response|RedirectResponse
    {
        if (!Passport::check($request)) {
            return redirect()->route('home')->withErrors(['login' => 'Авторизуйтесь']);
        }

        return $next($request);
    }
}
