<?php
class M {
  public $db;
  function init() { global $wpdb; $this->db = $wpdb; }
  function q() { $id = $_GET['x']; return $this->db->query($this->db->prepare("SELECT %d", $id)); } // NO flag (prepare)
  function bad() { $id = $_GET['y']; return $this->db->query("SELECT " . $id); }  // SHOULD flag line 6
}
