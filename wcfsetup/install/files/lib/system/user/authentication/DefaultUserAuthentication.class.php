<?php
namespace wcf\system\user\authentication;
use wcf\data\user\User;
use wcf\data\user\UserEditor;
use wcf\system\exception\ErrorException;
use wcf\system\exception\UserInputException;
use wcf\util\exception\CryptoException;
use wcf\util\CryptoUtil;
use wcf\util\HeaderUtil;
use wcf\util\JSON;
use wcf\util\PasswordUtil;

/**
 * Default user authentication implementation that uses the username to identify users.
 * 
 * @author	Marcel Werk
 * @copyright	2001-2015 WoltLab GmbH
 * @license	GNU Lesser General Public License <http://opensource.org/licenses/lgpl-license.php>
 * @package	com.woltlab.wcf
 * @subpackage	system.user.authentication
 * @category	Community Framework
 */
class DefaultUserAuthentication extends AbstractUserAuthentication {
	/**
	 * @see	\wcf\system\user\authentication\IUserAuthentication::supportsPersistentLogins()
	 */
	public function supportsPersistentLogins() {
		return true;
	}
	
	/**
	 * @see	\wcf\system\user\authentication\IUserAuthentication::storeAccessData()
	 */
	public function storeAccessData(User $user, $username, $password) {
		$password = hash('sha256', $password);
		$userEditor = new UserEditor($user);
		
		// no cookieHash exists yet
		if (!$user->cookieHash) {
			list(, $token) = explode(':', PasswordUtil::getHash($password));
			$info = password_get_info($token);
			if ($info['algo'] !== PASSWORD_BCRYPT) {
				throw new \BadMethodCallException('Algorithms other than PASSWORD_BCRYPT are not implemented');
			}
			
			$userEditor->update(['cookieHash' => substr($token, 0, 29).':'.hash_hmac('sha256', $token, $user->password)]);
		}
		else {
			try {
				list($salt) = explode(':', $user->cookieHash);
				$token = crypt($password, $salt);
			}
			catch (ErrorException $e) {
				// saved information are broken
				$userEditor->update(['cookieHash' => '']);
				return;
			}
		}
		
		try {
			$cookie = CryptoUtil::createSignedString(JSON::encode([
				'userID' => $user->userID,
				'token' => $token
			]));
			
			HeaderUtil::setCookie('autologin', $cookie, TIME_NOW + 365 * 24 * 3600);
		}
		catch (CryptoException $e) {
			\wcf\functions\exception\logThrowable($e);
		}
	}
	
	/**
	 * @see	\wcf\system\user\authentication\IUserAuthentication::loginManually()
	 */
	public function loginManually($username, $password, $userClassname = 'wcf\data\user\User') {
		$user = $this->getUserByLogin($username);
		$userSession = (get_class($user) == $userClassname ? $user : new $userClassname(null, null, $user));
		
		if ($userSession->userID == 0) {
			throw new UserInputException('username', 'notFound');
		}
		
		// check password
		if (!$userSession->checkPassword($password)) {
			throw new UserInputException('password', 'false');
		}
		
		return $userSession;
	}
	
	/**
	 * @see	\wcf\system\user\authentication\IUserAuthentication::loginAutomatically()
	 */
	public function loginAutomatically($persistent = false, $userClassname = 'wcf\data\user\User') {
		if (!$persistent) return null;
		
		try {
			// clean up old autologin cookie version
			HeaderUtil::setCookie('user', '');
			HeaderUtil::setCookie('password', '');
			
			if (isset($_COOKIE[COOKIE_PREFIX.'autologin'])) {
				$data = CryptoUtil::getValueFromSignedString($_COOKIE[COOKIE_PREFIX.'autologin']);
				if ($data === null) return $user = null;
				
				$data = JSON::decode($data);
				if (!($user = $this->getUserAutomatically($data['userID'], $data['token'], $userClassname))) {
					return $user = null;
				}
				
				return $user;
			}
			
			return $user = null;
		}
		finally {
			if ($user === null) HeaderUtil::setCookie('autologin', '');
		}
	}
	
	/**
	 * Returns a user object by given login name.
	 * 
	 * @param	string			$login
	 * @return	\wcf\data\user\User
	 */
	protected function getUserByLogin($login) {
		return User::getUserByUsername($login);
	}
	
	/**
	 * Returns a user object or null on failure.
	 * 
	 * @param	integer		$userID
	 * @param	string		$token
	 * @param	string		$userClassname
	 * @return	\wcf\data\user\User
	 */
	protected function getUserAutomatically($userID, $token, $userClassname = 'wcf\data\user\User') {
		$user = new $userClassname($userID);
		if (!$user->userID) return null;
		list(, $cookieHash) = explode(':', $user->cookieHash);
		
		if (!CryptoUtil::secureCompare(hash_hmac('sha256', $token, $user->password), $cookieHash)) {
			return null;
		}
		
		return $user;
	}
	
	/**
	 * @deprecated 2.2 - This method always throws, do not use it any more.
	 */
	protected function checkCookiePassword($user, $password) {
		return $user->checkCookiePassword($password);
	}
}
