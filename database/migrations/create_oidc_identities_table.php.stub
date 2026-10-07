<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create(config('oidc.identities_table', 'oidc_identities'), function (Blueprint $table) {
            $table->id();
            $table->morphs('authenticatable');
            $table->string('issuer');
            $table->string('subject');
            $table->string('email')->nullable();
            $table->string('name')->nullable();
            $table->json('claims')->nullable();
            $table->text('id_token')->nullable();
            $table->text('access_token')->nullable();
            $table->text('refresh_token')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->timestamps();

            $table->unique(['issuer', 'subject']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists(config('oidc.identities_table', 'oidc_identities'));
    }
};
