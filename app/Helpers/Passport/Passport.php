<?php

namespace App\Helpers\Passport;

use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

class Passport
{
    /**
     * Токен для подтверждения авторизации
     * @var ?string
     */
    private static ?string $access_token;

    /**
     * Токен для обновления access_token
     * @var ?string
     */
    private static ?string $refresh_token;

    /**
     * До какого времени действует access_token
     * @var ?string
     */
    private static ?string $expires_in;

    /**
     * Обновляет токены
     * @return bool
     */
    private static function refresh(): bool
    {
        $response = Http::asForm()->post(config('services.bee_id.url'). 'oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => self::$refresh_token,
            'client_id' => config('services.bee_id.id'),
            'client_secret' => config('services.bee_id.secret'),
            'scope' => '',
        ]);

        if (!$response->ok()) {
            return false;
        }

        self::saveTokens($response->json());

        return true;
    }

    /**
     * Сохранение токенов
     * @param $data
     * @return void
     */
    private static function saveTokens($data): void
    {
        self::$access_token = $data['access_token'];
        self::$refresh_token = $data['refresh_token'];
        self::$expires_in = $data['expires_in'];

        cookie()->queue('access_token', self::$access_token);
        cookie()->queue('refresh_token', self::$refresh_token);
        cookie()->queue('expires_in', self::$expires_in);
    }

    /**
     * Возвращает access_token
     * @return string|null
     */
    public static function getAccessToken(): ?string
    {
        return self::$access_token ?? null;
    }

    /**
     * Проверка авторизации
     * @param Request $request
     * @return bool
     */
    public static function check(Request $request): bool
    {
        self::$access_token = $request->cookie('access_token');
        self::$refresh_token = $request->cookie('refresh_token');
        self::$expires_in = $request->cookie('expires_in');

        //Проверка на существование токенов
        if (!self::$access_token || !self::$refresh_token || !self::$expires_in) {
            return false;
        }

        //Проверка на время жизни токенов
        if (now() > Carbon::create(self::$expires_in) && !self::refresh()) {
            return false;
        }

        //Если в кеше нет пользователя
        if (!Cache::has(self::$access_token) && !self::getUser()) {
            return false;
        }

        return true;
    }

    /**
     * Получение данных пользователя
     * @return bool
     */
    public static function getUser(): bool
    {
        $response = Http::withHeaders([
            'Accept' => 'application/json',
            'Authorization' => 'Bearer '.self::$access_token,
        ])->get(config('services.bee_id.url') . 'api/user');

        if (!$response->ok()) {
            return false;
        }

        Cache::put(self::$access_token, $response->json(), now()->addMinutes(10));

        return true;
    }

    /**
     * Возвращает данные авторизованного пользователя
     * @return ?object
     */
    public static function authUser(): ?object
    {
        $user = Cache::get(self::getAccessToken());

        if ($user) {
            return (object) $user;
        }

        return null;
    }
}
