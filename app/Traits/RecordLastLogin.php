<?php
namespace App\Traits;
use App\Models\User;
use Carbon\Carbon;

trait RecordLastLogin{
    public static function recordLogin($id){
        $user = User::find($id);

        $user->last_logged_in = Carbon::now();
        $user->save();
    }
}