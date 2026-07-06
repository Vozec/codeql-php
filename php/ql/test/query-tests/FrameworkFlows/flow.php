<?php
// Yii
function yii1($request, $connection) {
  $id = $request->getQueryParam('id');                       // yii source
  $connection->createCommand("SELECT * FROM t WHERE id=" . $id);  // WANT SQLi line 5
}
function yii2(\yii\web\Request $request, $c) {
  $c->createCommand("DELETE FROM t WHERE x=" . $request->post('x'));  // WANT SQLi line 8 (typed Request::post)
}
// CakePHP
function cake1(\Cake\Http\ServerRequest $request, \Cake\Database\Connection $connection) {
  $connection->query("SELECT * FROM t WHERE n='" . $request->getData('name') . "'");  // WANT SQLi line 12
}
// CodeIgniter
function ci1($input, $db) {
  $x = $input->get_post('x');                                // ci source (method)
  $db->simple_query("SELECT * FROM t WHERE id=" . $x);       // WANT SQLi line 17
}
