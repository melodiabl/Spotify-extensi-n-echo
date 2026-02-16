package dev.brahmkshatriya.echo.extension

import dev.brahmkshatriya.echo.common.clients.AlbumClient
import dev.brahmkshatriya.echo.common.clients.ArtistClient
import dev.brahmkshatriya.echo.common.clients.ExtensionClient
import dev.brahmkshatriya.echo.common.clients.FollowClient
import dev.brahmkshatriya.echo.common.clients.HomeFeedClient
import dev.brahmkshatriya.echo.common.clients.LibraryFeedClient
import dev.brahmkshatriya.echo.common.clients.LikeClient
import dev.brahmkshatriya.echo.common.clients.LoginClient
import dev.brahmkshatriya.echo.common.clients.LyricsClient
import dev.brahmkshatriya.echo.common.clients.PlaylistClient
import dev.brahmkshatriya.echo.common.clients.PlaylistEditClient
import dev.brahmkshatriya.echo.common.clients.RadioClient
import dev.brahmkshatriya.echo.common.clients.SaveClient
import dev.brahmkshatriya.echo.common.clients.SearchFeedClient
import dev.brahmkshatriya.echo.common.clients.ShareClient
import dev.brahmkshatriya.echo.common.clients.TrackClient
import dev.brahmkshatriya.echo.common.helpers.ClientException
import dev.brahmkshatriya.echo.common.helpers.ContinuationCallback.Companion.await
import dev.brahmkshatriya.echo.common.helpers.PagedData
import dev.brahmkshatriya.echo.common.helpers.WebViewRequest
import dev.brahmkshatriya.echo.common.models.Album
import dev.brahmkshatriya.echo.common.models.Artist
import dev.brahmkshatriya.echo.common.models.EchoMediaItem
import dev.brahmkshatriya.echo.common.models.Feed
import dev.brahmkshatriya.echo.common.models.Feed.Companion.toFeed
import dev.brahmkshatriya.echo.common.models.Feed.Companion.toFeedData
import dev.brahmkshatriya.echo.common.models.ImageHolder
import dev.brahmkshatriya.echo.common.models.ImageHolder.Companion.toImageHolder
import dev.brahmkshatriya.echo.common.models.Lyrics
import dev.brahmkshatriya.echo.common.models.NetworkRequest
import dev.brahmkshatriya.echo.common.models.NetworkRequest.Companion.toGetRequest
import dev.brahmkshatriya.echo.common.models.Playlist
import dev.brahmkshatriya.echo.common.models.Radio
import dev.brahmkshatriya.echo.common.models.Shelf
import dev.brahmkshatriya.echo.common.models.Streamable
import dev.brahmkshatriya.echo.common.models.Streamable.Media.Companion.toMedia
import dev.brahmkshatriya.echo.common.models.Streamable.Source.Companion.toSource
import dev.brahmkshatriya.echo.common.models.Tab
import dev.brahmkshatriya.echo.common.models.Track
import dev.brahmkshatriya.echo.common.models.User
import dev.brahmkshatriya.echo.common.settings.SettingString
import dev.brahmkshatriya.echo.common.settings.SettingSwitch
import dev.brahmkshatriya.echo.common.settings.Settings
import dev.brahmkshatriya.echo.extension.spotify.Base62
import dev.brahmkshatriya.echo.extension.spotify.Queries
import dev.brahmkshatriya.echo.extension.spotify.SpotifyApi
import dev.brahmkshatriya.echo.extension.spotify.SpotifyApi.Companion.userAgent
import dev.brahmkshatriya.echo.extension.spotify.mercury.MercuryConnection
import dev.brahmkshatriya.echo.extension.spotify.models.AccountAttributes
import dev.brahmkshatriya.echo.extension.spotify.models.ArtistOverview
import dev.brahmkshatriya.echo.extension.spotify.models.GetAlbum
import dev.brahmkshatriya.echo.extension.spotify.models.Item
import dev.brahmkshatriya.echo.extension.spotify.models.Metadata4Track
import dev.brahmkshatriya.echo.extension.spotify.models.Metadata4Track.Format.MP4_128
import dev.brahmkshatriya.echo.extension.spotify.models.Metadata4Track.Format.MP4_256
import dev.brahmkshatriya.echo.extension.spotify.models.Metadata4Track.Format.OGG_VORBIS_160
import dev.brahmkshatriya.echo.extension.spotify.models.Metadata4Track.Format.OGG_VORBIS_320
import dev.brahmkshatriya.echo.extension.spotify.models.Metadata4Track.Format.OGG_VORBIS_96
import dev.brahmkshatriya.echo.extension.spotify.models.UserProfileView
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import okhttp3.Request
import java.io.EOFException
import java.io.File
import java.io.InputStream
import java.math.BigInteger
import java.net.URLDecoder
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

open class SpotifyExtension(val clientId: String, val clientSecret: String) : ExtensionClient, LoginClient.WebView,
    SearchFeedClient, HomeFeedClient, LibraryFeedClient, LyricsClient, ShareClient,
    TrackClient, LikeClient, RadioClient, SaveClient,
    AlbumClient, PlaylistClient, ArtistClient, FollowClient, PlaylistEditClient {

    override suspend fun getSettingItems() = listOf(
        SettingString(
            "Spotify Client ID",
            "spotifyClientId",
            "Your Spotify Application Client ID",
            clientId
        ),
        SettingString(
            "Spotify Client Secret",
            "spotifyClientSecret",
            "Your Spotify Application Client Secret",
            clientSecret
        ),
        SettingSwitch(
            "Show Canvas",
            "show_canvas",
            "Whether to show background video canvas in songs",
            showCanvas
        ),
        SettingSwitch(
            "Crop Covers",
            "crop_covers",
            "Whether to crop artist and users images to fill the whole circle",
            cropCovers
        )
    )

    private val showCanvas get() = setting.getBoolean("show_canvas") ?: true
    private val cropCovers get() = setting.getBoolean("crop_covers") ?: true

    lateinit var setting: Settings
    override fun setSettings(settings: Settings) {
        setting = settings
    }

    open val filesDir = File("spotify")
    val api by lazy { SpotifyApi(filesDir, clientId, clientSecret) }
    val queries by lazy { Queries(api) }

    @OptIn(ExperimentalEncodingApi::class)
    override val webViewRequest = object : WebViewRequest.Cookie<List<User>> {
        private val secureRandom = SecureRandom()
        private val codeVerifierBytes = ByteArray(32).apply { secureRandom.nextBytes(this) }
        private val codeVerifier = Base64.UrlSafe.encode(codeVerifierBytes).substringBefore("=")
        private val codeChallenge = Base64.UrlSafe.encode(MessageDigest.getInstance("SHA-256").digest(codeVerifier.toByteArray())).substringBefore("=")

        private val redirectUri = "https://localhost:8080/callback"
        private val scopes = "user-read-private user-read-email user-library-read user-library-modify playlist-read-private playlist-modify-private playlist-modify-public streaming"

        override val initialUrl =
            "https://accounts.spotify.com/authorize?response_type=code&client_id=$clientId&scope=$scopes&redirect_uri=$redirectUri&code_challenge_method=S256&code_challenge=$codeChallenge".toGetRequest(mapOf(userAgent))
        override val stopUrlRegex =
            Regex("$redirectUri\\?code=.*")

        override suspend fun onStop(url: NetworkRequest, cookie: String): List<User> {
            val code = url.url.substringAfter("code=").substringBefore("&")
            val tokenResponse = api.web.getAccessTokenFromCode(code, codeVerifier, redirectUri)
            api.setCookie(cookie) // Keep the cookie for other web-based calls if needed
            api.web.accessToken = tokenResponse.access_token
            api.web.refreshToken = tokenResponse.refresh_token
            api.web.tokenExpiration = System.currentTimeMillis() + (tokenResponse.expires_in * 1000) - (5 * 60 * 1000)

            val userProfile = queries.profileAttributes().json.toUser().copy(
                extras = mapOf(
                    "cookie" to cookie,
                    "accessToken" to tokenResponse.access_token,
                    "refreshToken" to (tokenResponse.refresh_token ?: ""),
                    "tokenExpiration" to api.web.tokenExpiration.toString()
                )
            )
            return listOf(userProfile)
        }
    }

    override fun setLoginUser(user: User?) {
        api.setCookie(user?.extras?.get("cookie"))
        api.web.accessToken = user?.extras?.get("accessToken")
        api.web.refreshToken = user?.extras?.get("refreshToken")
        api.web.tokenExpiration = user?.extras?.get("tokenExpiration")?.toLong() ?: 0
        api.setUser(user?.id)
        this.user = user
        this.product = null
    }

    private var user: User? = null
    override suspend fun getCurrentUser(): User? {
        return queries.profileAttributes().json.toUser()
    }

    private var product: AccountAttributes.Product? = null
    private suspend fun hasPremium(): Boolean {
        if (api.cookie == null) return false
        if (product == null) product = queries.accountAttributes().json.data.me.account.product
        return product != AccountAttributes.Product.FREE
    }

    private fun getBrowsePage(): Feed.Data<Shelf> = PagedData.Single {
        queries.browseAll().json.data.browseStart.sections.toShelves(queries, cropCovers)
    }.toFeedData()

    override suspend fun loadSearchFeed(query: String): Feed<Shelf> {
        if (query.isBlank()) return Feed(listOf()) { getBrowsePage() }
        val (shelves, tabs) = queries.searchDesktop(query).json.data.searchV2
            .toShelvesAndTabs(query, queries, cropCovers)
        return Feed(tabs) { tab ->
            when (tab?.id) {
                "ARTISTS" -> paged {
                    queries.searchArtist(query, it).json.data.searchV2.artists
                        .toItemShelves(cropCovers)
                }

                "TRACKS" -> paged {
                    queries.searchTrack(query, it).json.data.searchV2.tracksV2
                        .toItemShelves(cropCovers)
                }

                "ALBUMS" -> paged {
                    queries.searchAlbum(query, it).json.data.searchV2.albumsV2
                        .toItemShelves(cropCovers)
                }

                "PLAYLISTS" -> paged {
                    queries.searchPlaylist(query, it).json.data.searchV2.playlists
                        .toItemShelves(cropCovers)
                }

                "GENRES" -> paged {
                    queries.searchGenres(query, it).json.data.searchV2.genres
                        .toCategoryShelves(queries, cropCovers)
                }

                "EPISODES" -> paged {
                    queries.searchEpisode(query, it).json.data.searchV2.episodes
                        .toItemShelves(cropCovers)
                }

                "SHOWS" -> paged {
                    queries.searchShow(query, it).json.data.searchV2.shows
                        .toItemShelves(cropCovers)
                }

                "USERS" -> paged {
                    queries.searchUser(query, it).json.data.searchV2.users
                        .toItemShelves(cropCovers)
                }

                else -> shelves.toFeedData()
            }
        }
    }

    private fun <T> paged(block: suspend (Int) -> Feed.Data<T>): Feed.Data<T> {
        return PagedData.Continuous(0, 50, block)
    }

    override suspend fun loadHomeFeed(): Feed<Shelf> {
        return queries.home().json.data.home.sectionContainer.sections.toShelves(queries, cropCovers)
            .toFeed()
    }

    override suspend fun loadLibraryFeed(user: User): Feed<Shelf> {
        val library = queries.library(user.id).json.data.me.library
        val shelves = mutableListOf<Shelf>()
        shelves.add(library.toShelf(cropCovers))
        library.playlists?.let { shelves.add(it.toShelf(cropCovers)) }
        library.artists?.let { shelves.add(it.toShelf(cropCovers)) }
        library.albums?.let { shelves.add(it.toShelf(cropCovers)) }
        return shelves.toFeed()
    }

    override suspend fun loadStreamable(streamable: Streamable): Streamable {
        val id = streamable.id.substringAfter("spotify:track:")
        val track = queries.trackInfo(id).json
        val hasOgg = track.hasOgg()
        val hasMp4 = track.hasMp4()
        val isPlayable = track.isPlayable

        if (!isPlayable) throw ClientException.Unavailable("This track is not available in your region.")

        val media = mutableListOf<Streamable.Media>()
        if (hasOgg && hasPremium()) {
            track.file.forEach { file ->
                val format = file.format ?: return@forEach
                if (format.isOgg()) {
                    media.add(
                        oggStream(streamable.copy(id = file.fileId, extras = mapOf("gid" to track.toGid())))
                    )
                }
            }
        }
        if (hasMp4) {
            track.file.forEach { file ->
                val format = file.format ?: return@forEach
                if (format.isMp4()) {
                    media.add(
                        widevineStream(streamable.copy(id = file.fileId))
                    )
                }
            }
        }

        return streamable.copy(media = media)
    }

    override suspend fun loadTrack(track: Track): Track {
        val id = track.id.substringAfter("spotify:track:")
        return queries.trackInfo(id).json.toTrack(cropCovers)
    }

    override suspend fun loadAlbum(album: Album): Album {
        val id = album.id.substringAfter("spotify:album:")
        val res = queries.getAlbum(id)
        return res.json.toAlbum(res.raw, cropCovers)
    }

    override suspend fun loadPlaylist(playlist: Playlist): Playlist {
        val id = playlist.id.substringAfter("spotify:playlist:")
        return queries.getPlaylist(id).json.toPlaylist(cropCovers)
    }

    override suspend fun setLiked(item: EchoMediaItem, liked: Boolean) {
        val id = item.id.substringAfter("spotify:track:")
        if (liked) queries.like(id) else queries.unlike(id)
    }

    override suspend fun setSaved(item: EchoMediaItem, saved: Boolean) {
        val id = item.id.substringAfter("spotify:album:")
        if (saved) queries.save(id) else queries.unsave(id)
    }

    override suspend fun setFollowing(artist: Artist, following: Boolean) {
        when (val type = artist.id.substringAfter(":").substringBefore(":")) {
            "artist" -> {
                val id = artist.id.substringAfter("spotify:artist:")
                if (following) queries.followArtists(id)
                else queries.unfollowArtists(id)
            }

            "user" -> {
                val id = artist.id.substringAfter("spotify:user:")
                if (following) queries.followUsers(id)
                else queries.unfollowUsers(id)
            }

            else -> throw IllegalArgumentException("Unsupported artist type: $type")
        }
    }

    override suspend fun loadFeed(artist: Artist): Feed<Shelf> {
        return when (val type = artist.id.substringAfter(":").substringBefore(":")) {
            "artist" -> {
                val res = api.json.decode<ArtistOverview>(artist.extras["raw"]!!)
                res.data.artistUnion.toShelves(queries, cropCovers)
            }

            "user" -> {
                val res = api.json.decode<UserProfileView>(artist.extras["raw"]!!)
                val id = artist.id.substringAfter("spotify:user:")
                listOfNotNull(
                    res.toShelf(),
                    queries.profileFollowers(id).json.toShelf("${id}_followers", "Followers"),
                    queries.profileFollowing(id).json.toShelf("${id}_following", "Following")
                )
            }

            else -> throw IllegalArgumentException("Unsupported artist type: $type")
        }.toFeed(Feed.Buttons(showPlayAndShuffle = true))
    }

    override suspend fun loadArtist(artist: Artist): Artist {
        when (val type = artist.id.substringAfter(":").substringBefore(":")) {
            "artist" -> {
                val res = queries.queryArtistOverview(artist.id)
                return res.json.data.artistUnion.toArtist(null, cropCovers)!!.copy(
                    extras = mapOf("raw" to res.raw)
                )
            }

            "user" -> {
                val id = artist.id.substringAfter("spotify:user:")
                val profile = queries.profileWithPlaylists(id)
                return profile.json.toArtist()!!.copy(
                    extras = mapOf("raw" to profile.raw)
                )
            }

            else -> throw IllegalArgumentException("Unsupported artist type: $type")
        }
    }

    override suspend fun searchTrackLyrics(clientId: String, track: Track) = PagedData.Single {
        val id = track.id.substringAfter("spotify:track:")
        val image = track.cover as ImageHolder.NetworkRequestImageHolder
        val lyrics = runCatching { queries.colorLyrics(id, image.request.url).json.lyrics }
            .getOrNull() ?: return@Single emptyList<Lyrics>()
        var last = Long.MAX_VALUE
        val list = lyrics.lines?.reversed()?.mapNotNull {
            val start = it.startTimeMs?.toLong()!!
            val item = Lyrics.Item(
                it.words ?: return@mapNotNull null,
                startTime = start,
                endTime = last,
            )
            last = start
            item
        }?.reversed() ?: return@Single emptyList<Lyrics>()
        listOf(
            Lyrics(
                id = track.id,
                title = track.title,
                subtitle = lyrics.providerDisplayName,
                lyrics = Lyrics.Timed(list)
            )
        )
    }.toFeed()

    override suspend fun loadLyrics(lyrics: Lyrics) = lyrics

    private suspend fun widevineStream(streamable: Streamable): Streamable.Media.Server {
        val accessToken = api.getWebAccessToken()
        val storage = queries.storageResolve(streamable.id).json
        val url = storage.cdnUrl.firstOrNull() 
            ?: throw Exception("No CDN URL found for ${streamable.id}")
        
        val decryption = Streamable.Decryption.Widevine(
            "https://spclient.wg.spotify.com/widevine-license/v1/audio/license"
                .toGetRequest(
                    mapOf(
                        "Authorization" to "Bearer $accessToken",
                    )
                ),
            true
        )
        return Streamable.Source.Http(
            request = url.toGetRequest(),
            decryption = decryption,
        ).toMedia()
    }

    val time = 5000L
    var lastFetched = 0L
    val mutex = Mutex()

    private suspend fun oggStream(streamable: Streamable): Streamable.Media {
        val fileId = streamable.id

        val key = mutex.withLock {
            val lastTime = System.currentTimeMillis() - lastFetched
            if (lastTime < time) delay(time - lastTime)
            val gid = streamable.extras["gid"]
                ?: throw IllegalArgumentException("GID is required for streaming")
            val storedToken = api.getMercuryToken()
            lastFetched = System.currentTimeMillis()
            MercuryConnection.getAudioKey(storedToken, gid, fileId)
        }
        val url = queries.storageResolve(streamable.id).json.cdnUrl.random()
        return Streamable.InputProvider { position, length ->
            decryptFromPosition(key, AUDIO_IV, position, length) { pos, len ->
                val range = "bytes=$pos-${len?.toString() ?: ""}"
                val request = Request.Builder().url(url)
                    .header("Range", range)
                    .build()
                val resp = api.client.newCall(request).await()
                val actualLength = resp.header("Content-Length")?.toLong() ?: -1L
                resp.body.byteStream() to actualLength
            }
        }.toSource(fileId).toMedia()
    }

    private suspend fun decryptFromPosition(
        key: ByteArray,
        iv: BigInteger,
        position: Long,
        length: Long,
        provider: suspend (Long, Long?) -> Pair<InputStream, Long>,
    ): Pair<InputStream, Long> {
        val newPos = position + 0xA7
        val alignedPos = newPos - (newPos % 16)
        val blockOffset = (newPos % 16).toInt()
        val len = if (length < 0) null else length + newPos - 1
        val (input, contentLength) = provider(alignedPos, len)

        val ivCounter = iv.add(BigInteger.valueOf(alignedPos / 16))
        val ivBytes = ivCounter.to16ByteArray()

        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            IvParameterSpec(ivBytes)
        )

        val cipherStream = CipherInputStream(input, cipher)

        cipherStream.skipBytes(blockOffset)
        return cipherStream to contentLength - blockOffset
    }

    companion object {
        private val AUDIO_IV = BigInteger("72e067fbddcbcf77ebe8bc643f630d93", 16)
        private fun BigInteger.to16ByteArray(): ByteArray {
            val full = toByteArray()
            return when {
                full.size == 16 -> full
                full.size > 16 -> full.copyOfRange(full.size - 16, full.size)
                else -> ByteArray(16 - full.size) + full
            }
        }

        fun InputStream.skipBytes(len: Int) {
            var remaining = len
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (remaining > 0) {
                val toRead = minOf(remaining, buffer.size)
                val read = read(buffer, 0, toRead)
                if (read == -1) break // EOF
                remaining -= read
            }
            if (remaining > 0) throw EOFException("Reached end of stream before reading $len bytes")
        }
    }
}
