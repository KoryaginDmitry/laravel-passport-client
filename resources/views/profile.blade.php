@extends('layouts.main_layout')

@section('title', 'Профиль')

@section('content')

<h4>Добрый день, {{ $user->name }}. Ваша почта - {{ $user->email }}</h4>

<a href="{{ route('logout') }}">Выйти</a>

@endsection
