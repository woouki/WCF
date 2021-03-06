<?php
namespace wcf\system\cache\builder;

/**
 * Caches a list of the most active members.
 * 
 * @author	Marcel Werk
 * @copyright	2001-2016 WoltLab GmbH
 * @license	GNU Lesser General Public License <http://opensource.org/licenses/lgpl-license.php>
 * @package	WoltLabSuite\Core\System\Cache\Builder
 */
class MostActiveMembersCacheBuilder extends AbstractSortedUserCacheBuilder {
	/**
	 * @inheritDoc
	 */
	protected $maxLifetime = 600;
	
	/**
	 * @inheritDoc
	 */
	protected $positiveValuesOnly = true;
	
	/**
	 * @inheritDoc
	 */
	protected $sortField = 'activityPoints';
}
