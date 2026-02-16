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
import dev.brahmkshatriya.echo.common.settings.SettingTextInput
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
        SettingTextInput(
            "Spotify Client ID",
            "spotifyClientId",
            "Your Spotify Application Client ID",
            clientId
        ),
        SettingTextInput(
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
            api.web.tokenExpiration = System.currentTimeMillis() + (tokenResponse.access_token_expires_in * 1000) - (5 * 60 * 1000)

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
                    queries.searchEpisodes(query, it).json.data.searchV2.episodes
                        .toItemShelves(cropCovers)
                }

                else -> PagedData.Single { shelves }.toFeedData()
            }
        }
    }

    override suspend fun loadHomeFeed(): Feed<Shelf> = Feed(listOf()) { getBrowsePage() }

    override suspend fun loadLibraryFeed(): Feed<Shelf> = Feed(listOf()) {
        PagedData.Single {
            queries.libraryDesktop().json.data.me.libraryV3.items.toShelves(cropCovers)
        }.toFeedData()
    }

    override suspend fun loadLyrics(track: Track): Lyrics? {
        val trackId = track.id.substringAfterLast(":")
        return queries.lyrics(trackId).json.toLyrics()
    }

    override suspend fun onShare(item: EchoMediaItem): String {
        return "https://open.spotify.com/${item.type.name.lowercase()}/${item.id.substringAfterLast(":")}"
    }

    override suspend fun loadTrack(track: Track, isDownload: Boolean): Track {
        val trackId = track.id.substringAfterLast(":")
        val metadata = queries.trackMetadata(trackId).json
        return metadata.toTrack(track, cropCovers)
    }

    override suspend fun loadStreamableMedia(streamable: Streamable, isDownload: Boolean): Streamable.Media {
        val trackId = streamable.id.substringAfterLast(":")
        val metadata = queries.trackMetadata(trackId).json
        val fileId = metadata.file.firstOrNull { it.format == OGG_VORBIS_160 }?.file_id
            ?: metadata.file.firstOrNull { it.format == OGG_VORBIS_96 }?.file_id
            ?: metadata.file.firstOrNull { it.format == OGG_VORBIS_320 }?.file_id
            ?: throw ClientException("No ogg file found")

        val key = api.mercury.getTrackKey(trackId, fileId)
        val url = "https://audio-ak-spotify-com.akamaized.net/audio/$fileId"
        
        return Streamable.Media(
            sources = listOf(url.toSource()),
            extras = mapOf("key" to Base64.Default.encode(key))
        )
    }

    override suspend fun loadFeed(track: Track): Feed<Shelf>? = null
    override suspend fun loadFeed(album: Album): Feed<Shelf>? = null
    override suspend fun loadFeed(playlist: Playlist): Feed<Shelf>? = null

    override suspend fun likeItem(item: EchoMediaItem, shouldLike: Boolean) {
        val id = item.id.substringAfterLast(":")
        if (shouldLike) queries.likeTrack(id) else queries.unlikeTrack(id)
    }

    override suspend fun isItemLiked(item: EchoMediaItem): Boolean {
        val id = item.id.substringAfterLast(":")
        return queries.checkLikedTracks(listOf(id)).json.firstOrNull() ?: false
    }

    override suspend fun loadRadio(radio: Radio): Radio = radio
    override suspend fun loadTracks(radio: Radio): Feed<Track> = Feed(listOf()) {
        PagedData.Single {
            queries.radio(radio.id.substringAfterLast(":")).json.data.lookup.tracks.toTracks(cropCovers)
        }.toFeedData()
    }

    override suspend fun loadTracks(album: Album): Feed<Track>? = Feed(listOf()) {
        PagedData.Single {
            queries.album(album.id.substringAfterLast(":")).json.data.albumUnion.tracksV2.items.map { it.track.toTrack(cropCovers) }
        }.toFeedData()
    }

    override suspend fun loadTracks(playlist: Playlist): Feed<Track> = Feed(listOf()) {
        PagedData.Single {
            queries.playlist(playlist.id.substringAfterLast(":")).json.data.playlistV2.content.items.mapNotNull { it.itemV2.data.toTrack(cropCovers) }
        }.toFeedData()
    }

    override suspend fun radio(item: EchoMediaItem, context: EchoMediaItem?): Radio {
        return Radio(
            id = "spotify:radio:${item.id.substringAfterLast(":")}",
            title = "Radio: ${item.title}",
            cover = item.cover
        )
    }

    override suspend fun saveToLibrary(item: EchoMediaItem, shouldSave: Boolean) {
        likeItem(item, shouldSave)
    }

    override suspend fun isItemSaved(item: EchoMediaItem): Boolean {
        return isItemLiked(item)
    }

    override suspend fun isFollowing(item: EchoMediaItem): Boolean {
        val id = item.id.substringAfterLast(":")
        return queries.checkFollowingArtists(listOf(id)).json.firstOrNull() ?: false
    }

    override suspend fun getFollowersCount(item: EchoMediaItem): Long? = null

    override suspend fun followItem(item: EchoMediaItem, shouldFollow: Boolean) {
        val id = item.id.substringAfterLast(":")
        if (shouldFollow) queries.followArtist(id) else queries.unfollowArtist(id)
    }

    override suspend fun listEditablePlaylists(track: Track?): List<Pair<Playlist, Boolean>> {
        return queries.libraryDesktop().json.data.me.libraryV3.items
            .filter { it.type == "PLAYLIST" }
            .map { it.toPlaylist(cropCovers) to false }
    }

    override suspend fun createPlaylist(title: String, description: String?): Playlist {
        throw ClientException("Not implemented")
    }

    override suspend fun deletePlaylist(playlist: Playlist) {
        throw ClientException("Not implemented")
    }

    override suspend fun editPlaylistMetadata(playlist: Playlist, title: String, description: String?) {
        throw ClientException("Not implemented")
    }

    override suspend fun addTracksToPlaylist(playlist: Playlist, tracks: List<Track>, index: Int, new: List<Track>) {
        throw ClientException("Not implemented")
    }

    override suspend fun removeTracksFromPlaylist(playlist: Playlist, tracks: List<Track>, indexes: List<Int>) {
        throw ClientException("Not implemented")
    }

    override suspend fun loadAlbum(album: Album): Album {
        return queries.album(album.id.substringAfterLast(":")).json.data.albumUnion.toAlbum(cropCovers)
    }

    override suspend fun loadArtist(artist: Artist): Artist {
        return queries.artist(artist.id.substringAfterLast(":")).json.data.artistUnion.toArtist(cropCovers)
    }

    override suspend fun loadPlaylist(playlist: Playlist): Playlist {
        return queries.playlist(playlist.id.substringAfterLast(":")).json.data.playlistV2.toPlaylist(cropCovers)
    }

    private fun <T> paged(loader: suspend (String?) -> List<T>): Feed.Data<T> = PagedData.Single {
        loader(null)
    }.toFeedData()
}
