<?php
// Voyager (thedevdojo/voyager) BREAD SQL injection — GitHub issue #4943 (v1.4, May 2020), affecting every
// model's browse view. The admin BREAD browse controller reads the sort column (`order_by`) and the search
// column (`key`) straight from the request and passes them as the COLUMN argument of Eloquent's
// query builder — orderBy($column,…) and where($column,…). Laravel does NOT escape column identifiers
// (only bound *values*), so a request-controlled column injects SQL, e.g.
//   /admin/users/?order_by=id&sort_order=asc,(select...)   or   ?key=id)+AND+(select...)--
// Later versions added in_array()/pluck()->contains() whitelists on these fields; this reproduces the
// pre-whitelist shape, faithful to src/Http/Controllers/VoyagerBaseController.php.
// Source: Illuminate Request->get('order_by' / 'key'). Sink: Builder->orderBy / ->where (column arg 0).
// Ref: github.com/thedevdojo/voyager/issues/4943
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class VoyagerBaseController
{
    public function index(Request $request)
    {
        $search  = (object) ['value' => $request->get('s'), 'key' => $request->get('key'), 'filter' => $request->get('filter')];
        $orderBy = $request->get('order_by');       // source: request sort column
        $sortOrder = $request->get('sort_order');

        $query = DB::table('data_types');

        if ($search->value != '' && $search->key && $search->filter) {
            $search_filter = ($search->filter == 'equals') ? '=' : 'LIKE';
            $search_value  = ($search->filter == 'equals') ? $search->value : '%'.$search->value.'%';
            $searchField   = 'data_types.'.$search->key;    // request-controlled column identifier
            // ruleid: php/sql-injection
            $query->where($searchField, $search_filter, $search_value);   // column arg is NOT escaped -> SQLi
        }

        if ($orderBy) {
            $querySortOrder = (!empty($sortOrder)) ? $sortOrder : 'desc';
            // ruleid: php/sql-injection
            $results = $query->orderBy($orderBy, $querySortOrder)->get();  // column arg is NOT escaped -> SQLi
            return $results;
        }

        return $query->get();
    }
}
