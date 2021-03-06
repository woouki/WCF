/**
 * Provides the media manager dialog for selecting media for Redactor editors.
 *
 * @author	Matthias Schmidt
 * @copyright	2001-2016 WoltLab GmbH
 * @license	GNU Lesser General Public License <http://opensource.org/licenses/lgpl-license.php>
 * @module	WoltLabSuite/Core/Media/Manager/Editor
 */
define(['Core', 'Dictionary', 'Dom/Traverse', 'Language', 'Ui/Dialog', 'WoltLabSuite/Core/Controller/Clipboard', 'WoltLabSuite/Core/Media/Manager/Base'],
	function(Core, Dictionary, DomTraverse, Language, UiDialog, ControllerClipboard, MediaManagerBase) {
	"use strict";
	
	/**
	 * @constructor
	 */
	function MediaManagerEditor(options) {
		options = Core.extend({
			callbackInsert: null
		}, options);
		
		MediaManagerBase.call(this, options);
		
		this._forceClipboard = true;
		this._activeButton = null;
		this._buttons = elByClass(this._options.buttonClass || 'jsMediaEditorButton');
		for (var i = 0, length = this._buttons.length; i < length; i++) {
			this._buttons[i].addEventListener(WCF_CLICK_EVENT, this._click.bind(this));
		}
		this._mediaToInsert = new Dictionary();
		this._mediaToInsertByClipboard = false;
	}
	Core.inherit(MediaManagerEditor, MediaManagerBase, {
		/**
		 * @see	WoltLabSuite/Core/Media/Manager/Base#_addButtonEventListeners
		 */
		_addButtonEventListeners: function() {
			MediaManagerEditor._super.prototype._addButtonEventListeners.call(this);
			
			if (!this._mediaManagerMediaList) return;
			
			var listItems = DomTraverse.childrenByTag(this._mediaManagerMediaList, 'LI');
			for (var i = 0, length = listItems.length; i < length; i++) {
				var listItem = listItems[i];
				
				var insertIcon = elByClass('jsMediaInsertButton', listItem)[0];
				if (insertIcon) {
					insertIcon.classList.remove('jsMediaInsertButton');
					insertIcon.addEventListener(WCF_CLICK_EVENT, this._openInsertDialog.bind(this));
				}
			}
		},
		
		/**
		 * Builds the dialog to setup inserting media files.
		 */
		_buildInsertDialog: function() {
			var thumbnailOptions = '';
			
			var thumbnailSizes = this._getThumbnailSizes();
			for (var i = 0, length = thumbnailSizes.length; i < length; i++) {
				thumbnailOptions += '<option value="' + thumbnailSizes[i] + '">' + Language.get('wcf.media.insert.imageSize.' + thumbnailSizes[i]) + '</option>';
			}
			thumbnailOptions += '<option value="original">' + Language.get('wcf.media.insert.imageSize.original') + '</option>';
			
			var dialog = '<div class="section">'
			/*+ (this._mediaToInsert.size > 1 ? '<dl>'
				+ '<dt>' + Language.get('wcf.media.insert.type') + '</dt>'
				+ '<dd>'
					+ '<select name="insertType">'
						+ '<option value="separate">' + Language.get('wcf.media.insert.type.separate') + '</option>'
						+ '<option value="gallery">' + Language.get('wcf.media.insert.type.gallery') + '</option>'
					+ '</select>'
				+ '</dd>'
			+ '</dl>' : '')*/
			+ '<dl class="thumbnailSizeSelection">'
				+ '<dt>' + Language.get('wcf.media.insert.imageSize') + '</dt>'
				+ '<dd>'
					+ '<select name="thumbnailSize">'
						+ thumbnailOptions
					+ '</select>'
				+ '</dd>'
			+ '</dl>'
			+ '</div>'
			+ '<div class="formSubmit">'
				+ '<button class="buttonPrimary">' + Language.get('wcf.global.button.insert') + '</button>'
			+ '</div>';
			
			UiDialog.open({
				_dialogSetup: (function() {
					return {
						id: this._getInsertDialogId(),
						options: {
							onClose: this._editorClose.bind(this),
							onSetup: function(content) {
								elByClass('buttonPrimary', content)[0].addEventListener(WCF_CLICK_EVENT, this._insertMedia.bind(this));
								
								// toggle thumbnail size selection based on selected insert type
								/*var insertType = elBySel('select[name=insertType]', content);
								if (insertType !== null) {
									var thumbnailSelection = elByClass('thumbnailSizeSelection', content)[0];
									insertType.addEventListener('change', function(event) {
										if (event.currentTarget.value === 'gallery') {
											elHide(thumbnailSelection);
										}
										else {
											elShow(thumbnailSelection);
										}
									});
								}*/
								var thumbnailSelection = elBySel('.thumbnailSizeSelection', content);
								elShow(thumbnailSelection);
							}.bind(this),
							title: Language.get('wcf.media.insert')
						},
						source: dialog
					};
				}).bind(this)
			});
		},
		
		/**
		 * @see	WoltLabSuite/Core/Media/Manager/Base#_click
		 */
		_click: function(event) {
			this._activeButton = event.currentTarget;
			
			MediaManagerEditor._super.prototype._click.call(this, event);
		},
		
		/**
		 * @see	WoltLabSuite/Core/Media/Manager/Base#_clipboardAction
		 */
		_clipboardAction: function(actionData) {
			MediaManagerEditor._super.prototype._clipboardAction.call(this, actionData);
			
			if (actionData.data.actionName === 'com.woltlab.wcf.media.insert') {
				this.insertMedia(actionData.data.parameters.objectIDs, true);
			}
		},
		
		/**
		 * Returns the id of the insert dialog based on the media files to be inserted.
		 * 
		 * @return	{string}	insert dialog id
		 */
		_getInsertDialogId: function() {
			var dialogId = 'mediaInsert';
			
			this._mediaToInsert.forEach(function(media, mediaId) {
				dialogId += '-' + mediaId;
			});
			
			return dialogId;
		},
		
		/**
		 * Returns the supported thumbnail sizes (excluding `original`) for all media images to be inserted.
		 * 
		 * @return	{string[]}
		 */
		_getThumbnailSizes: function() {
			var sizes = [];
			
			var supportedSizes = ['small', 'medium', 'large'];
			var size, supportSize;
			for (var i = 0, length = supportedSizes.length; i < length; i++) {
				size = supportedSizes[i];
				
				supportSize = true;
				this._mediaToInsert.forEach(function(media) {
					if (!media[size + 'ThumbnailType']) {
						supportSize = false;
					}
				});
				
				if (supportSize) {
					sizes.push(size);
				}
			}
			
			return sizes;
		},
		
		/**
		 * Inserts media files into redactor.
		 * 
		 * @param	{Event?}	event
		 * @param	{string?}	thumbnailSize
		 */
		_insertMedia: function(event, thumbnailSize) {
			var insertType = 'separate';
			
			// update insert options with selected values if method is called by clicking on 'insert' button
			// in dialog
			if (event) {
				UiDialog.close(this._getInsertDialogId());
				
				var dialogContent = event.currentTarget.closest('.dialogContent');
				
				/*if (this._mediaToInsert.size > 1) {
					insertType = elBySel('select[name=insertType]', dialogContent).value;
				}*/
				thumbnailSize = elBySel('select[name=thumbnailSize]', dialogContent).value;
			}
			
			if (this._options.callbackInsert !== null) {
				this._options.callbackInsert(this._mediaToInsert, insertType, thumbnailSize);
			}
			else {
				if (insertType === 'separate') {
					this._options.editor.buffer.set();
					
					this._mediaToInsert.forEach(this._insertMediaItem.bind(this, thumbnailSize));
				}
				else {
					this._insertMediaGallery();
				}
			}
			
			if (this._mediaToInsertByClipboard) {
				var mediaIds = [];
				this._mediaToInsert.forEach(function(media) {
					mediaIds.push(media.mediaID);
				});
				
				ControllerClipboard.unmark('com.woltlab.wcf.media', mediaIds);
			}
			
			this._mediaToInsert = new Dictionary();
			this._mediaToInsertByClipboard = false;
			
			// close manager dialog
			UiDialog.close(this);
		},
		
		/**
		 * Inserts a series of uploaded images using a slider.
		 * 
		 * @protected
		 */
		_insertMediaGallery: function() {
			var mediaIds = [];
			this._mediaToInsert.forEach(function(item) {
				mediaIds.push(item.mediaID);
			});
			
			this._options.editor.buffer.set();
			this._options.editor.insert.text("[wsmg='" + mediaIds.join(',') + "'][/wsmg]");
		},
		
		/**
		 * Inserts a single media item.
		 * 
		 * @param       {string}        thumbnailSize   preferred image dimension, is ignored for non-images
		 * @param       {Object}        item            media item data
		 * @protected
		 */
		_insertMediaItem: function(thumbnailSize, item) {
			if (item.isImage) {
				var sizes = ['small', 'medium', 'large', 'original'];
				
				// check if size is actually available
				var available = '', size;
				for (var i = 0; i < 4; i++) {
					size = sizes[i];
					
					if (item[size + 'ThumbnailHeight'] != 0) {
						available = size;
						
						if (thumbnailSize == size) {
							break;
						}
					}
				}
				
				thumbnailSize = available;
				
				if (!thumbnailSize) thumbnailSize = 'original';
				
				var link = item.link;
				if (thumbnailSize !== 'original') {
					link = item[thumbnailSize + 'ThumbnailLink'];
				}
				
				this._options.editor.insert.html('<img src="' + link + '" class="woltlabSuiteMedia" data-media-id="' + item.mediaID + '" data-media-size="' + thumbnailSize + '">');
			}
			else {
				this._options.editor.insert.text("[wsm='" + item.mediaID + "'][/wsm]");
			}
		},
		
		/**
		 * Handles clicking on the insert button.
		 * 
		 * @param	{Event}		event		insert button click event
		 */
		_openInsertDialog: function(event) {
			this.insertMedia([~~elData(event.currentTarget, 'object-id')]);
		},
		
		/**
		 * Prepares insertion of the media files with the given ids.
		 * 
		 * @param	{array<int>}	mediaIds		ids of the media files to be inserted
		 * @param	{boolean?}	insertedByClipboard	is true if the media files are inserted by clipboard
		 */
		insertMedia: function(mediaIds, insertedByClipboard) {
			this._mediaToInsert = new Dictionary();
			this._mediaToInsertByClipboard = insertedByClipboard || false;
			
			// open the insert dialog if all media files are images
			var imagesOnly = true, media;
			for (var i = 0, length = mediaIds.length; i < length; i++) {
				media = this._mediaData.get(mediaIds[i]);
				this._mediaToInsert.set(media.mediaID, media);
				
				if (!media.isImage) {
					imagesOnly = false;
				}
			}
			
			if (imagesOnly) {
				var thumbnailSizes = this._getThumbnailSizes();
				if (thumbnailSizes.length) {
					UiDialog.close(this);
					var dialogId = this._getInsertDialogId();
					if (UiDialog.getDialog(dialogId)) {
						UiDialog.openStatic(dialogId);
					}
					else {
						this._buildInsertDialog();
					}
				}
				else {
					this._insertMedia(undefined, 'original');
				}
			}
			else {
				this._insertMedia();
			}
		},
		
		/**
		 * @see	WoltLabSuite/Core/Media/Manager/Base#getMode
		 */
		getMode: function() {
			return 'editor';
		},
		
		/**
		 * @see	WoltLabSuite/Core/Media/Manager/Base#setupMediaElement
		 */
		setupMediaElement: function(media, mediaElement) {
			MediaManagerEditor._super.prototype.setupMediaElement.call(this, media, mediaElement);
			
			// add media insertion icon
			var buttons = elBySel('nav.buttonGroupNavigation > ul', mediaElement);
			
			var listItem = elCreate('li');
			buttons.appendChild(listItem);
			
			listItem.innerHTML = '<a><span class="icon icon16 fa-plus jsTooltip jsMediaInsertButton" data-object-id="' + media.mediaID + '" title="' + Language.get('wcf.media.button.insert') + '"></span> <span class="invisible">' + Language.get('wcf.media.button.insert') + '</span></a>';
		}
	});
	
	return MediaManagerEditor;
});
