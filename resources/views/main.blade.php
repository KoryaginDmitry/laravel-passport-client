@extends('layouts.main_layout')

@section('title', 'Гостевая страница')

@section('content')

    @error('login')
        <p>{{ $message }}</p>
    @enderror

    @if($user)
       <a href="{{ route('profile') }}">Перейти в профиль</a>
    @else
        <a href="{{ route('auth') }}">Авторизоваться с помощью bee-id</a>
    @endif

@endsection
