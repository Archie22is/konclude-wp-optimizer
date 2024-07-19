<?php
/**
 * @package         Konclude WordPress Optimizer
 * @author          Archie Makuwa
 * @copyright       2024 Konclude (Pty) Ltd
 * 
 * Plugin Name:     Konclude WordPress Optimizer
 * Description:     A plugin to enhance the security of your WordPress site by setting various security and optimizations settings.
 * Version:         1.0.5
 * Author:          Konclude (Archie Makuwa)
 * Author URI:      https://www.konclu.de
 */

 if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

// Add security headers based on options
function kwo_add_security_headers() {
    // Always append the X-Frame-Options header
    header('X-Frame-Options: SAMEORIGIN');

    // Always set the X-Content-Type-Options header
    header('X-Content-Type-Options: nosniff');

    // Always set the X-XSS-Protection header
    header('X-XSS-Protection: 1; mode=block');

    // Get options
    $options = get_option('kwo_options');

    // Base CSP
    $csp = "default-src 'self'; ";
    $csp .= "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://*.google.com https://*.gstatic.com https://*.googleapis.com https://cdn.jsdelivr.net https://www.gstatic.com/recaptcha/ blob:; ";
    $csp .= "style-src 'self' 'unsafe-inline' https://*.google.com https://*.gstatic.com https://*.googleapis.com https://fonts.googleapis.com https://cdn.jsdelivr.net; ";
    $csp .= "font-src 'self' data: https://*.gstatic.com https://fonts.googleapis.com https://cdn.jsdelivr.net; ";
    $csp .= "img-src 'self' data: https://*.google.com https://*.gstatic.com https://*.googleapis.com https://secure.gravatar.com https://linkmon.sanren.ac.za https://chpc.ac.za; ";
    $csp .= "frame-src 'self' https://www.google.com https://maps.google.com https://docs.google.com; ";
    $csp .= "connect-src 'self' https://maps.googleapis.com; ";
    $csp .= "worker-src 'self' blob:; "; // Allow blob URLs for workers

    // Add custom domains from options
    if (!empty($options['custom_csp_domains'])) {
        $custom_domains = explode(',', $options['custom_csp_domains']);
        foreach ($custom_domains as $domain) {
            $domain = trim($domain);
            $csp .= "script-src $domain; ";
            $csp .= "style-src $domain; ";
            $csp .= "font-src $domain; ";
            $csp .= "img-src $domain; ";
            $csp .= "frame-src $domain; ";
            $csp .= "connect-src $domain; ";
        }
    }

    header("Content-Security-Policy: $csp");

    if (!empty($options['hsts'])) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
    }
    if (!empty($options['referrer_policy'])) {
        header('Referrer-Policy: no-referrer-when-downgrade');
    }
    if (!empty($options['permissions_policy'])) {
        header('Permissions-Policy: geolocation=(self), microphone=()');
    }
}
add_action('send_headers', 'kwo_add_security_headers');

// Disable XML-RPC to prevent brute force attacks
$options = get_option('kwo_options');
if (!empty($options['disable_xmlrpc'])) {
    add_filter('xmlrpc_enabled', '__return_false');
}

// Disable file editing from the admin panel
if (!empty($options['disable_file_editing'])) {
    define('DISALLOW_FILE_EDIT', true);
}

// Add options page
function kwo_add_admin_menu() {
    add_options_page(
        'Konclude WordPress Optimizer',
        'Security Headers',
        'manage_options',
        'kwo',
        'kwo_options_page'
    );
}
add_action('admin_menu', 'kwo_add_admin_menu');

// Register settings
function kwo_settings_init() {
    register_setting('kwo', 'kwo_options');

    add_settings_section(
        'kwo_section_headers',
        __('Security Headers', 'kwo'),
        'kwo_section_headers_cb',
        'kwo'
    );

    add_settings_field(
        'hsts',
        __('HTTP Strict Transport Security (HSTS)', 'kwo'),
        'kwo_hsts_render',
        'kwo',
        'kwo_section_headers'
    );

    add_settings_field(
        'referrer_policy',
        __('Referrer Policy', 'kwo'),
        'kwo_referrer_policy_render',
        'kwo',
        'kwo_section_headers'
    );

    add_settings_field(
        'permissions_policy',
        __('Permissions Policy', 'kwo'),
        'kwo_permissions_policy_render',
        'kwo',
        'kwo_section_headers'
    );

    add_settings_section(
        'kwo_section_other',
        __('Other Security Options', 'kwo'),
        'kwo_section_other_cb',
        'kwo'
    );

    add_settings_field(
        'disable_xmlrpc',
        __('Disable XML-RPC', 'kwo'),
        'kwo_disable_xmlrpc_render',
        'kwo',
        'kwo_section_other'
    );

    add_settings_field(
        'disable_file_editing',
        __('Disable File Editing', 'kwo'),
        'kwo_disable_file_editing_render',
        'kwo',
        'kwo_section_other'
    );

    add_settings_field(
        'custom_csp_domains',
        __('Custom CSP Domains', 'kwo'),
        'kwo_custom_csp_domains_render',
        'kwo',
        'kwo_section_headers'
    );
}
add_action('admin_init', 'kwo_settings_init');

function kwo_section_headers_cb() {
    echo __('Configure the HTTP security headers you want to enable.', 'kwo');
}

function kwo_section_other_cb() {
    echo __('Additional security options.', 'kwo');
}

function kwo_hsts_render() {
    $options = get_option('kwo_options');
    ?>
    <input type='checkbox' name='kwo_options[hsts]' <?php checked($options['hsts'], 1); ?> value='1'>
    <?php
}

function kwo_referrer_policy_render() {
    $options = get_option('kwo_options');
    ?>
    <input type='checkbox' name='kwo_options[referrer_policy]' <?php checked($options['referrer_policy'], 1); ?> value='1'>
    <?php
}

function kwo_permissions_policy_render() {
    $options = get_option('kwo_options');
    ?>
    <input type='checkbox' name='kwo_options[permissions_policy]' <?php checked($options['permissions_policy'], 1); ?> value='1'>
    <?php
}

function kwo_disable_xmlrpc_render() {
    $options = get_option('kwo_options');
    ?>
    <input type='checkbox' name='kwo_options[disable_xmlrpc]' <?php checked($options['disable_xmlrpc'], 1); ?> value='1'>
    <?php
}

function kwo_disable_file_editing_render() {
    $options = get_option('kwo_options');
    ?>
    <input type='checkbox' name='kwo_options[disable_file_editing]' <?php checked($options['disable_file_editing'], 1); ?> value='1'>
    <?php
}

function kwo_custom_csp_domains_render() {
    $options = get_option('kwo_options');
    ?>
    <textarea name='kwo_options[custom_csp_domains]' rows='5' cols='50'><?php echo esc_textarea($options['custom_csp_domains']); ?></textarea>
    <p class="description"><?php _e('Enter additional domains to be included in the CSP directives, separated by commas.', 'kwo'); ?></p>
    <?php
}

function kwo_options_page() {
    ?>
    <form action='options.php' method='post'>
        <h2>Konclude WordPress Optimizer</h2>
        <?php
        settings_fields('kwo');
        do_settings_sections('kwo');
        submit_button();
        ?>
    </form>
    <?php
}
