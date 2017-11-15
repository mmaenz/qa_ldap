<?php
/* This class represents behavior and properties
/* for a generic LDAP server.
/* Tested against OpenLDAP.
*/

class GenericLDAPServer extends LDAPServer {
  private $dn;
  private $authenticatedUser;

  public function bindToLDAP($user,$pass) {
    $ldap_search_strings = explode('/', qa_opt('ldap_login_generic_search'));
    $groupCN = "cn=q2a,ou=groups,dc=igret,dc=de";
    foreach ($ldap_search_strings as &$search_post) {
      // check whether the search string contains USERNAME
      if ( strpos($search_post, 'USERNAME') !== false ) {
        $this->dn = str_replace("USERNAME", $user, $search_post);
        // Check if it authenticates
	error_reporting(E_ALL^ E_WARNING);
        $bind = ldap_bind($this->con,$this->dn, $pass);
        error_reporting(E_ALL);
        //we have to preserve the username entered if auth was succesfull
        if($bind) {
		if (!empty($groupCN)) {
			$search = ldap_search($this->con, $groupCN, "memberUid=".$user);
                        $info = ldap_get_entries($this->con, $search);
                        if (is_bool($info) || $info["count"]==0 || $info[0]["count"]==0) {
                        	error_log($user." - No membership for Q2A!");
                                $user = false;
				return false;
                        }
		}
	  $this->authenticatedUser = $user;
          return $bind;
        }
      }
    }
    return false;
  }

  public function getUserAttributes() {
    $fname_tag = qa_opt('ldap_login_fname');
    $sname_tag = qa_opt('ldap_login_sname');
    $mail_tag = qa_opt('ldap_login_mail');

    // Run query to determine user's name
    $filter = qa_opt('ldap_login_filter');
    $attributes = array($fname_tag, $sname_tag, $mail_tag);
    $search = ldap_search($this->con, $this->dn, "(&(uid=".$this->authenticatedUser.")".$filter.")");
    $data = ldap_get_entries($this->con, $search);

    $fname = $data[0][strtolower($fname_tag)][0];
    $sname = $data[0][strtolower($sname_tag)][0];
    $mail  = $data[0][strtolower($mail_tag)][0];

    return array( $fname, $sname, $mail, $this->authenticatedUser);
  }
}

?>
