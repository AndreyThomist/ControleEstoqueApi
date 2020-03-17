<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Laravel\Passport\Passport;
use App\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Carbon\Carbon;
class LoginController extends Controller
{

    public function register(Request $request)
    {
       $validacao = Validator::make($request->all(),[
            "name" => "required|min:1|max:255",
            "email" => "required|min:1|max:255|unique:users",
            "password" => "required",
        ],[
            "name.required" => "Campo Nome Obrigatório",
            "name.max" => "Campo Nome deve ter 255 caracteres ou menos",
            "email.required" => "Campo Email Obrigatório",
            "email.max" => "Campo email deve ter 255 caracteres ou menos",
            "email.unique" => "Email já em uso",
            "password.required" => "Campo Senha obrigatório"
        ]);
        if($validacao->fails()){
            $errors = $validacao->errors()->getMessages();
            return [
                "success" => false,
                "message" => $errors
            ];
        }
        try{
           $request['password'] = Hash::make($request['password']);
           $user = User::create($request->all());
           $token = $user->createToken('testeapi');
           return [
                "success" => true,
                "access_token" => "Bearer ".$token->accessToken,
                "expires_at" => Carbon::parse($token->token->expires_at)->format('Y-m-d H:i:s')
           ] ;
        }catch(Exception $e){
            return [
                "success" => false,
                "message" => $e->getMessage()
            ];
        }
    }
    public function login(Request $request)
    {
        $validacao = Validator::make($request->all(),[
            "email" => "required",
            "password" => "required",
        ],[
            "email.required" => "Campo Email Obrigatório",
            "password.required" => "Senha obrigatória"
        ]);
        if($validacao->fails()){
            $errors = $validacao->errors()->getMessages();
            return [
                "success" => false,
                "message" => $errors
            ];
        }
        $credentials =  $request->only('email','password');
        if(Auth::attempt($credentials)){
           $user = User::where('email',$request['email'])->first();
           $token = $user->createToken('testeapi');
           return [
            "success" => true,
            "access_token" => "Bearer ". $token->accessToken,
            "expires_at" => Carbon::parse($token->token->expires_at)->format('Y-m-d H:i:s')
            ] ;
        }   
    }
    public function logout(Request $request)
    {
      $user = $request->user();
      foreach($user->tokens as  $token){
          $token->revoke();
      }
    }
}
