<?php
namespace wcf\system\page\handler;
use wcf\data\page\Page;
use wcf\data\user\online\UserOnline;
use wcf\system\cache\runtime\UserRuntimeCache;
use wcf\system\WCF;

/**
 * Implementation of the `IOnlineLocationPageHandler` interface for user-bound pages.
 *
 * @author	Matthias Schmidt
 * @copyright	2001-2016 WoltLab GmbH
 * @license	GNU Lesser General Public License <http://opensource.org/licenses/lgpl-license.php>
 * @package	WoltLabSuite\Core\System\Page\Handler
 * @since	3.0
 */
trait TUserOnlineLocationPageHandler {
	use TOnlineLocationPageHandler;
	
	/**
	 * @see	IOnlineLocationPageHandler::getOnlineLocation()
	 */
	public function getOnlineLocation(Page $page, UserOnline $user) {
		if ($user->pageObjectID === null) {
			return '';
		}
		
		$userObject = UserRuntimeCache::getInstance()->getObject($user->pageObjectID);
		if ($userObject === null) {
			return '';
		}
		
		return WCF::getLanguage()->getDynamicVariable('wcf.page.onlineLocation.'.$page->identifier, ['user' => $userObject]);
	}
	
	/**
	 * @see	IOnlineLocationPageHandler::prepareOnlineLocation()
	 */
	public function prepareOnlineLocation(/** @noinspection PhpUnusedParameterInspection */Page $page, UserOnline $user) {
		if ($user->pageObjectID !== null) {
			UserRuntimeCache::getInstance()->cacheObjectID($user->pageObjectID);
		}
	}
}