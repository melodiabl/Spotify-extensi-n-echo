package dev.brahmkshatriya.echo.extension.spotify

import dev.brahmkshatriya.echo.common.helpers.ContinuationCallback.Companion.await
import kotlinx.serialization.Serializable
import okhttp3.Credentials
import okhttp3.FormBody
import okhttp3.Request
import java.io.File

class TokenManagerWeb(private val api: SpotifyApi, private val clientId: String, private val clientSecret: String) {

    var accessToken: String? = null
    var refreshToken: String? = null
    var tokenExpiration: Long = 0

    fun clear() {
        accessToken = null
        refreshToken = null
        tokenExpiration = 0
    }

    suspend fun getToken(): String {
        if (accessToken == null || tokenExpiration < System.currentTimeMillis()) {
            if (refreshToken != null) {
                refreshAccessToken()
            } else {
                throw Error("No refresh token available. User needs to log in.")
            }
        }
        return accessToken!!
    }

    suspend fun getAccessTokenFromCode(code: String, codeVerifier: String, redirectUri: String): TokenResponse {
        val requestBody = FormBody.Builder()
            .add("grant_type", "authorization_code")
            .add("code", code)
            .add("redirect_uri", redirectUri)
            .add("client_id", clientId)
            .add("code_verifier", codeVerifier)
            .build()

        val request = Request.Builder()
            .url("https://accounts.spotify.com/api/token")
            .post(requestBody)
            .addHeader("Authorization", Credentials.basic(clientId, clientSecret))
            .build()

        val response = api.client.newCall(request).await()
        if (!response.isSuccessful) {
            throw Error("Failed to get access token: ${response.code} ${response.message}")
        }
        val responseBody = response.body.string()
        val tokenResponse = api.json.decode<TokenResponse>(responseBody)

        accessToken = tokenResponse.access_token
        refreshToken = tokenResponse.refresh_token
        tokenExpiration = System.currentTimeMillis() + (tokenResponse.expires_in * 1000) - (5 * 60 * 1000) // 5 minutes buffer

        return tokenResponse
    }

    private suspend fun refreshAccessToken() {
        val requestBody = FormBody.Builder()
            .add("grant_type", "refresh_token")
            .add("refresh_token", refreshToken!!)
            .add("client_id", clientId)
            .build()

        val request = Request.Builder()
            .url("https://accounts.spotify.com/api/token")
            .post(requestBody)
            .addHeader("Authorization", Credentials.basic(clientId, clientSecret))
            .build()

        val response = api.client.newCall(request).await()
        if (!response.isSuccessful) {
            throw Error("Failed to refresh access token: ${response.code} ${response.message}")
        }
        val responseBody = response.body.string()
        val tokenResponse = api.json.decode<TokenResponse>(responseBody)

        accessToken = tokenResponse.access_token
        refreshToken = tokenResponse.refresh_token ?: refreshToken // Refresh token might not be returned
        tokenExpiration = System.currentTimeMillis() + (tokenResponse.expires_in * 1000) - (5 * 60 * 1000)
    }

    @Serializable
    data class TokenResponse(
        val access_token: String,
        val token_type: String,
        val expires_in: Long,
        val refresh_token: String? = null,
        val scope: String? = null
    )

    class Error(message: String) : Exception(message)
}
