<?php
// WordPress
function wp1() { global $wpdb; $wpdb->get_results("SELECT * FROM t WHERE id=" . $_GET['id']); } // BUG SQLi (3)
function wp2() { wp_redirect($_GET['url']); }                              // BUG open redirect (4)
function wp3() { global $wpdb; echo esc_html($_GET['x']); }               // ok: esc_html
function wp4() { global $wpdb; $wpdb->get_var($wpdb->prepare("x %d", $_GET['id'])); } // ok: prepare
// Symfony / Doctrine
function sf1($em, $request) { $em->createQuery("SELECT u WHERE n=" . $request->getContent()); } // BUG SQLi (8)
function sf2($conn, $request) { $conn->executeQuery("SELECT " . $request->getClientIp()); }      // BUG SQLi (9)
// PrestaShop
function ps1($db) { $db->executeS("SELECT * FROM ps WHERE id=" . Tools::getValue('id')); }        // BUG SQLi (11)
function ps2($db) { $db->executeS("SELECT * FROM ps WHERE id=" . pSQL(Tools::getValue('id'))); }  // ok: pSQL
// TYPO3
function t3a($q) { $q->sql_query("SELECT * FROM x WHERE u=" . GeneralUtility::_GP('u')); }         // BUG SQLi (14)
// PrestaShop redirect (data-modelled open-redirect sink)
function ps3() { Tools::redirect(Tools::getValue('url')); }                                        // BUG open redirect (16)
