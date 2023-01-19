<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Auth\Events\Registered;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Validator;
use Laravel\Sanctum\PersonalAccessToken;
use Laravel\Socialite\Facades\Socialite;
// Registered
use App\Traits\RecordLastLogin;
use Carbon\Carbon;

class AuthenticationController extends Controller
{
    use RecordLastLogin;
    public function login(Request $request){
      
        if(Auth::attempt(['email' => $request->email, 'password' => $request->password])){ 
            $authUser = Auth::user(); 
            RecordLastLogin::recordLogin($authUser->id);
            $success['token'] =  $authUser->createToken('test')->plainTextToken; 
            $success['name'] =  $authUser->name;
            $success['email'] = $authUser->email;
            return response()->json([
                'status' => 200,
                'token' => $success['token'],
                'data' => [
                    'name' => $success['name'],
                    'email' => $success['email'],
                ]
            ],200);
        } 
        else{ 
            return response()->json([
                'status' => 500,
                'message' => 'Unathorized'
            ],500);
        } 
    }

    public function register(Request $request){

        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|email|unique:users,email,except,id',
            'password' => 'required',
            'confirm_password' => 'required|same:password',
        ]);

        if($validator->fails()){
                 return response()->json([
                'status' => 500,
                'message' => $validator->errors()
            ], 500);
        }

        $input = $request->all();
        $input['password'] = bcrypt($input['password']);
        $user = User::create($input);
        $success['token'] =  $user->createToken('test')->plainTextToken;
        $success['name'] =  $user->name;
        RecordLastLogin::recordLogin($user->id);
        event(new Registered($user));
        return response()->json([
            'status' => 200,
            'token' => $success['token']
        ],200);

 
    }

    public function logout(Request $request){
        $accessToken = $request->bearerToken();
        dd($accessToken);
        $token = PersonalAccessToken::findToken($accessToken);
        $token->delete();

        return response()->json([
            'status' => 200,
            'message' => 'logged out'
        ],200);
    }

    public function getCurrentUser(Request $request){
        $user = Auth::user();

        return response()->json([
            'status' => 200,
            'data' => $user
        ],200);
    }

    public function googleLogin(Request $request)
    {
        try {
            $user = Socialite::driver('google')->stateless()->user();
            $finduser = User::where('google_id', $user->id)->first();
            if($finduser){
                return response()->json([
                    'status' => 200,
                    'data' => $finduser
                ],200);
            }else{
                $provider = 'google';
                $providerUser = Socialite::driver($provider)->stateless()->user();
                $user = User::create([
                    'email' => $providerUser->getEmail(),
                    'name' => $providerUser->getName(),
                    'password' => Hash::make('password'),
                    'google_id' => $providerUser->id
                ]);
                $data =  [
                    'token' => $user->createToken('test')->plainTextToken,
                    'user' => $user,
                ];
                return response()->json($data, 200);
            }
        } catch (\Throwable $th) {
            return response()->json([
                'status' => 500,
                'message' => $th
            ],500);
        }
    }

    public function redirectToGoogle($provider)
    {
        return Socialite::driver($provider)->stateless()->redirect();
    }
}
