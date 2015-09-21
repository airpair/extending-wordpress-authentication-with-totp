By default, WordPress provides two pieces of information to identify users and separate them from one another: unique usernames and hashed passwords. For many small sites, this is plenty to protect user accounts from attack.

However, as WordPress continues to grow in popularity, so does the surface it presents to potential hackers. Even small sites have been breached by committed attackers. A stronger scheme being used by many sites today is _multi-factor authentication_.

This new scheme adds another element - something you have in your possession - to the authentication flow. First, a user provides their username and password. Then, they must provide a code generated _by a separate physical device_ to further verify their identity before being granted access to the site.

WordPress will likely support this more advanced authentication scheme in the near future, but there’s no reason you should wait. Instead, let’s walk through the steps to bring [time-based one-time password (TOTP)](https://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm) support to WordPress through a plugin. Once enabled, you can use an application on your phone ([Google Authenticator](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2&hl=en), [Windows Authenticator](https://www.microsoft.com/en-us/store/apps/authenticator/9wzdncrfj3rj), etc) to generate TOTP tokens and protect your account from prying eyes.

## Plugin Architecture

WordPress plugins are merely bundles of scripts (PHP and JavaScript) that live within a specific directory of a WordPress installation. When WordPress itself loads things up, it scans the `/wp-content/plugins` directory for available plugins and, based on some database fields dictating which plugins are active, `include()`s their scripts where necessary.

One of the most powerful features in WordPress is the way it allows itself to be [extended by plugins](http://codex.wordpress.org/Plugin_API/Hooks). You don't have to understand the entire code base, you just need to know which [_actions_](https://codex.wordpress.org/Plugin_API/Action_Reference) and [_filters_](http://codex.wordpress.org/Plugin_API/Filter_Reference) are exposed by WordPress.

**Actions** are effectively event hooks within WordPress. When something happens (a post is changed, a user logs in, a password field is printed, etc), WordPress fires an action. Plugins can register event handlers for these actions and, based on the event itself and arguments passed along with it, react in turn.

**Filters** are very similar to actions, but instead of allowing an event to occur, they present an opportunity for plugins to change a specific value before it's used elsewhere. A perfect example of a filter is the `the_content`; before printing post content to the screen, WordPress allows plugins to intercept and modify the post content. 

The WordPress template tag function, `the_content()`, fetches a post's content and passes it through a filter before returning it for the theme to use:

```php
function the_content( $more_link_text = null, $strip_teaser = false) {
	$content = get_the_content( $more_link_text, $strip_teaser );

	/**
	 * Filter the post content.
	 *
	 * @since 0.71
	 *
	 * @param string $content Content of the current post.
	 */
	$content = apply_filters( 'the_content', $content );
	$content = str_replace( ']]>', ']]&gt;', $content );
	echo $content;
}
```

A simple filter example to, say, append a Facebook Like button to the end of every post could look something like:

```php
function append_fb_like( $content ) {
    $content .= facebook_like_html();
    
    return $content;
}
add_filter( 'the_content', 'append_fb_like' );
```

Our TOTP plugin will leverage WordPress' action and filter structure to inject additional authentication mechanisms into the standard user login flow.

## Extend the User Profile

First things first, we need to present the option to enable TOTP for authentication to the user. To keep things simple, we'll present a minimalistic "Enable Two-Step Authentication" button to users who aren't authenticated.

![Enable Two-Step Authentication](https://s3-us-west-2.amazonaws.com/6675d06c-ea96-49d2-8788-c5bc5129fb4a/Enable-Two-Step.png)

When they click the button, the page will expand to present a QR code with their personal authentication credentials encoded. Scanning this code with an authentication app will add the site to the app and respond with a new authentication code. Entering this authentication code into the admin will link everything together.

![The QR code presented when enabling two-step authentication](https://s3-us-west-2.amazonaws.com/6675d06c-ea96-49d2-8788-c5bc5129fb4a/Two-Step-QR.png)

Once connected, we'll change the interface to present instead a "Disable Two-Step Authentication" button that will purge the associated device information from the system.

### Enable Button

Adding the enable button is a straight-forward matter of using WordPress action system to append new content to the bottom of the user profile/settings page. The necessary hooks are the `show_user_profile` and `edit_user_profile` actions:

```php
add_action( 'show_user_profile', 'user_options' );
add_action( 'edit_user_profile', 'user_options' );
```

The `user_options()` function referenced above ties everything together by adding the new "Two-Step Authentication" UI to the page, complete with a JavaScript-powered "Enable" button that toggles the QR code section open and closed:

```php
function user_options( $user ) {
    // If the user isn't set, bail
	if ( ! isset( $user->ID ) ) {
		return;
	}

    // Set a nonce field so we can validate our settings when items are saved
	wp_nonce_field( 'totp_options', '_nonce_totp_options', false );
	
	// Attempt to fetch the user's authenciation key from meta
	$key = get_user_meta( $user->ID, '_totp_key', true );
	$site_name = get_bloginfo( 'name', 'display' );

	?>
	<table class="form-table">
		<tr id="totp">
			<th><label for="totp-authcode">Two-Step Authentication</label></th>
			<td>
				<?php if ( empty( $key ) ) :
				    // If the key didn't exist, create one
					$key = generate_key(); ?>
					<button type="button" class="button button-secondary" onclick="jQuery('#totp-enable').toggle();">Enable</button>
				<?php else : ?>
					<!-- This comes later ... -->
				<?php endif; ?>
				<div id="totp-enable" style="display:none;">
					<br />
					<img src="<?php echo esc_url( get_qr_code( $site_name, $user->user_email, $key ) ); ?>" id="totp-qrcode" />
					<p><strong><?php echo esc_html( $key ); ?></strong></p>
					<p>Please scan the QR code or manually enter the key, then enter an authentication code from your app in order to complete setup</p>
					<p>
						<label for="totp-authcode">Authentication Code:</label>
						<input type="hidden" name="totp-key" value="<?php echo esc_attr( $key ) ?>" />
						<input type="tel" name="totp-authcode" id="totp-authcode" class="input" value="" size="20" pattern="[0-9]*" />
					</p>
				</div>
			</td>
		</tr>
	</table>

	<?php
}
```

The table itself is straight-forward when not in use: a label and a button. The button, though, uses jQuery to toggle the visibility of the larger QR code settings section.

### Secret Key

The binding of a mobile device with a site won't work without a secret key they can agree upon, though. For our purposes, we'll be using a randomly generated key of 16 characters in length:

```php
function generate_key( $bitsize = 128 ) {
	$base_32_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	if ( 8 > $bitsize || 0 !== $bitsize % 8 ) {
		wp_die( -1 );
	}

	$s = '';

	for ( $i = 0; $i < $bitsize / 8; $i++ ) {
		$s .= $base_32_chars[ rand( 0, 31 ) ];
	}

	return $s;
}
```

The Google Authenticator app can be made to work with shorter keys, but similar tools like Microsoft's Authenticator will freak out if the key is less than 16 characters long. To keep things clean, we're using a base-32 character space (all alphabet characters plus the numbers 2-7).

### QR Code

To generate a QR code, we'll use Google's Chart API tp process our string. You could always enter the generated secret key direction into an authenticator app, but using the camera built into a phone to scan the QR code is faster and less error prone.

For authentication, we need to scan a URL that looks like:

```
otpauth://totp/site-name:username?secret=0123456789ABCDEF&issuer=AirPair
```

This URL tells us we're configuring one-time password authentication, using a TOTP algorithm. It further specifies the name of the site to which we're authenticating, the user for whome we're logging in, and the organization issuing the TOTP challenge.

In PHP, these values are all sent to the Google API to generate a QR image:

```php
function get_qr_code( $site_name, $user, $key ) {
	$name = sanitize_title( $site_name ) . ':' . $user;
	$url = urlencode( 'otpauth://totp/' . $name . '?secret=' . $key );
	$url .= urlencode( '&issuer=' . urlencode( $site_name ) );
	return 'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=' . $url;
}
```

### Disable Button

The disable button is a bit simpler. Instead of toggling the visibility of any particular UI components, we'll instead use the button to trigger a small JavaScript routine. Our routine will first prompt the user to confirm that they're disabling two-step authentication, then will delete the key stored in the hidden field in the UI.

```php
<button type="button" 
        class="button button-secondary" 
        onclick="if(confirm('Are you sure you want to disable two-step authentication?')){jQuery('[name=totp-key]').val('');}">Disable</button>
```

The JavaScript uses a standard confirmation dialog and, if the user clicks "OK", flushes the stored key.

**Note:** At this point, the user still needs to click "Update Profile" to disassociate their mobile authenticator with their account. We're not wiring in AJAX functionality or immediate responses yet.

## Extend the Login Screen

There are two options available for extending the login screen:
1. Adding a new field to the existing username/password page
2. Adding a new page entirely between the username/password submission and the requested page.

We will take option #2 and add a new page. This gives us the ability to authenticate a user _first_ against their username and password pair before prompting for a second factor of authentication.

```php
function totp_login( $user_login, $user ) {
	$key = get_user_meta( $user->ID, '_totp_key', true );

	if ( empty( $key ) ) {
		return;
	}

	wp_clear_auth_cookie();

	show_two_factor_login( $user );
	exit;
}
add_action( 'wp_login', 'totp_login', 10, 2 );
```

After the username and password pair is submitted, WordPress will set an auth cookie by default and consider the user logged in. We don't necessarily want that. Instead, if the user has a two-factor authentication key set up, we want to clear their auth cookie and display the _second_ authentication form.

```php
function show_two_factor_login( $user ) {
	$login_nonce = create_login_nonce( $user->ID );
	if ( ! $login_nonce ) {
		wp_die( esc_html__( 'Could not save login nonce.' ) );
	}

	$redirect_to = isset( $_REQUEST['redirect_to'] ) ? $_REQUEST['redirect_to'] : $_SERVER['REQUEST_URI'];

	login_html( $user, $login_nonce['key'], $redirect_to );
}
```

The login nonce here merely helps protect the user from having their session hijacked while they sit on the secondary login page and checks their phone for their one-time password.

```php
function login_html( $user, $login_nonce, $redirect_to, $error_msg = '' ) {
	$rememberme = 0;
	if ( isset( $_REQUEST['rememberme'] ) && $_REQUEST['rememberme'] ) {
		$rememberme = 1;
	}

	login_header();

	if ( ! empty( $error_msg ) ) {
		echo '<div id="login_error"><strong>' . esc_html( $error_msg ) . '</strong><br /></div>';
	}
	?>

	<form name="validate_totp" id="loginform" action="<?php echo esc_url( site_url( 'wp-login.php?action=validate_totp', 'login_post' ) ); ?>" method="post" autocomplete="off">
		<input type="hidden" name="wp-auth-id"    id="wp-auth-id"    value="<?php echo esc_attr( $user->ID ); ?>" />
		<input type="hidden" name="wp-auth-nonce" id="wp-auth-nonce" value="<?php echo esc_attr( $login_nonce ); ?>" />
		<input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect_to ); ?>" />
		<input type="hidden" name="rememberme"    id="rememberme"    value="<?php echo esc_attr( $rememberme ); ?>" />

		<?php authentication_page( $user ); ?>
	</form>

	<p id="backtoblog">
		<a href="<?php echo esc_url( home_url( '/' ) ); ?>" title="Are you lost?"><?php echo sprintf( '&larr; Back to %s', get_bloginfo( 'title', 'display' ) ); ?></a>
	</p>

	<?php
	/** This action is documented in wp-login.php */
	do_action( 'login_footer' ); ?>
	<div class="clear"></div>
	</body>
	</html>
	<?php
}
```

```php
function authentication_page( $user ) {
	require_once( ABSPATH .  '/wp-admin/includes/template.php' );
	?>
	<p>
		<label for="authcode">Authentication Code:</label>
		<input type="tel" name="authcode" id="authcode" class="input" value="" size="20" pattern="[0-9]*" />
	</p>
	<?php
	submit_button( 'Authenticate' );
}
```

The mechanism for actually rendering the authentication page is two-fold. First, the `login_html()` function builds out all of the HTML necessary for the page, with the standard WordPress branding in place as well.

Second, the `authentication_page()` function renders the label and field for the authentication code and wires up a submit button so the user can send the information to WordPress.

## Validating the TOTP Token

The most important step of all, here, is validating that the TOTP token provided by the user is actually a valid token. We actually need to do this both when saving the secret key (above) and when logging the user in after they provide the token.

Validation itself is fairly easy:

```php
function is_valid_authcode( $key, $authcode ) {
	$max_ticks = apply_filters( 'totp-time-step-allowance', 4 );

	// Array of all ticks to allow, sorted using absolute value to test closest match first.
	$ticks = range( - $max_ticks, $max_ticks );
	usort( $ticks, __NAMESPACE__ . '\abssort' );

	$time = time() / 30;

	foreach ( $ticks as $offset ) {
		$log_time = $time + $offset;
		if ( calc_totp( $key, $log_time ) === $authcode ) {
			return true;
		}
	}
	return false;
}
```

This function will calculate a TOTP token for the current time, and four "ticks" on either side of the current time. The TOTP token provided is considered valid for up to 5 minutes (a "tick" occurs every 30 seconds, and a token is valid for up to 9 ticks).

The TOTP token itself is calculated using a standard algorthm that incorporates HMAC hashing and bit shifting to generate a reliable value. I won't explain the algorithm in too much detail here, but the code (and some supporting functions) is as follows:

```php
function calc_totp( $key, $step_count = false, $digits = 6, $hash = 'sha1', $time_step = 30 ) {
	$secret =  base32_decode( $key );

	if ( false === $step_count ) {
		$step_count = floor( time() / $time_step );
	}

	$timestamp = pack( 'J', $step_count );

	$hash = hash_hmac( $hash, $timestamp, $secret, true );

	$offset = ord( $hash[19] ) & 0xf;

	$code = (
		        ( ( ord( $hash[ $offset + 0 ] ) & 0x7f ) << 24 ) |
		        ( ( ord( $hash[ $offset + 1 ] ) & 0xff ) << 16 ) |
		        ( ( ord( $hash[ $offset + 2 ] ) & 0xff ) << 8 ) |
		        ( ord( $hash[ $offset + 3 ] ) & 0xff )
	        ) % pow( 10, $digits );

	return str_pad( $code, $digits, '0', STR_PAD_LEFT );
}

function base32_decode( $base32_string ) {
	$base32_string 	= strtoupper( $base32_string );

	if ( ! preg_match( '/^[ABCDEFGHIJKLMNOPQRSTUVWXYZ234567]+$/', $base32_string, $match ) ) {
		throw new Exception( 'Invalid characters in the base32 string.' );
	}

	$l 	= strlen( $base32_string );
	$n	= 0;
	$j	= 0;
	$binary = '';

	for ( $i = 0; $i < $l; $i++ ) {
		$n = $n << 5; // Move buffer left by 5
		$n = $n + strpos( 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', $base32_string[ $i ] ); 	// Add value into buffer.
		$j += 5; // Keep track of number of bits

		if ( $j >= 8 ) {
			$j -= 8;
			$binary .= chr( ( $n & ( 0xFF << $j ) ) >> $j );
		}
	}

	return $binary;
}
```

Once the user submits their authentication code, we hook in to WordPress' postback processing mechanism and check to see if the authentication code was valid:

```php
function validate_totp() {
	if ( ! isset( $_POST['wp-auth-id'], $_POST['wp-auth-nonce'] ) ) {
		return;
	}

	$user = get_userdata( $_POST['wp-auth-id'] );
	if ( ! $user ) {
		return;
	}

	$nonce = $_POST['wp-auth-nonce'];
	if ( true !== verify_login_nonce( $user->ID, $nonce ) ) {
		wp_safe_redirect( get_bloginfo( 'url' ) );
		exit;
	}

    // Here we explicity validate the user's submitted TOTP token
	if ( true !== validate_authentication( $user ) ) {
		do_action( 'wp_login_failed', $user->user_login );

		$login_nonce = create_login_nonce( $user->ID );
		if ( ! $login_nonce ) {
			return;
		}

		login_html( $user, $login_nonce['key'], $_REQUEST['redirect_to'], 'ERROR: Invalid verification code.' );
		exit;
	}

	delete_login_nonce( $user->ID );

	$rememberme = false;
	if ( isset( $_REQUEST['rememberme'] ) && $_REQUEST['rememberme'] ) {
		$rememberme = true;
	}

	wp_set_auth_cookie( $user->ID, $rememberme );

	$redirect_to = apply_filters( 'login_redirect', $_REQUEST['redirect_to'], $_REQUEST['redirect_to'], $user );
	wp_safe_redirect( $redirect_to );

	exit;
}
add_action( 'login_form_validate_totp', 'validate_totp' );

function validate_authentication( $user ) {
	$key = get_user_meta( $user->ID, '_totp_key', true );
	return is_valid_authcode( $key, $_REQUEST['authcode'] );
}
```

If the user's TOTP token is valid, WordPress will set the appropriate authentication cookie and forward them along to the page they originally requested (likely the admin dashboard). If the token is _invalid_, then WordPress will stay on the authentication page and prompt for a new submission.

## Looking forward

WordPress' flexibility makes it incredibly easy to extend in just about any direction. Today we focused specifically on extending things in terms of time-based one time password authentication. However, you could add in any form of two-step authentication you want.

Actually, there's a team working to fold TOTP, [universal two-factor authentication](https://www.yubico.com/applications/fido/), SMS-based authentication, and a couple of other mechanisms into WordPress as you read this. It's yet another example of how easy it is to add stronger security to WordPress.

A further step would be to integrate WordPress' authentication with the other apps powering your online presence. Thanks to the hookable functionality of WordPress, you can make any authentication provider serve as the base of user credentials. Truly-secure single-sign-on is just an extension of the various changes we've made above.