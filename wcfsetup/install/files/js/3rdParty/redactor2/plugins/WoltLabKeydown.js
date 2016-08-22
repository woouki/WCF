$.Redactor.prototype.WoltLabKeydown = function() {
	"use strict";
	
	var _tags = [];
	
	return {
		init: function () {
			this.keydown.onArrowDown = (function() {
				var tags = this.WoltLabKeydown._getBlocks();
				
				for (var i = 0; i < tags.length; i++) {
					if (tags[i]) {
						this.keydown.insertAfterLastElement(tags[i]);
						return false;
					}
				}
			}).bind(this);
			
			this.keydown.onArrowUp = (function() {
				var tags = this.WoltLabKeydown._getBlocks();
				
				for (var i = 0; i < tags.length; i++) {
					if (tags[i]) {
						this.keydown.insertBeforeFirstElement(tags[i]);
						return false;
					}
				}
			}).bind(this);
			
			var mpOnEnter = this.keydown.onEnter;
			this.keydown.onEnter = (function(e) {
				var isBlockquote = this.keydown.blockquote;
				if (isBlockquote) this.keydown.blockquote = false;
				
				mpOnEnter.call(this, e);
				
				if (isBlockquote) this.keydown.blockquote = isBlockquote;
			}).bind(this);
			
			var mpOnTab = this.keydown.onTab;
			this.keydown.onTab = (function(e, key) {
				if (!this.keydown.pre && $(this.selection.current()).closest('ul, ol', this.core.editor()[0]).length === 0) {
					return true;
				}
				
				return mpOnTab.call(this, e, key);
			}).bind(this);
		},
		
		register: function (tag) {
			if (_tags.indexOf(tag) === -1) {
				_tags.push(tag);
			}
		},
		
		_getBlocks: function () {
			var tags = [this.keydown.blockquote, this.keydown.pre, this.keydown.figcaption];
			
			for (var i = 0, length = _tags.length; i < length; i++) {
				tags.push(this.utils.isTag(this.keydown.current, _tags[i]))
			}
			
			return tags;
		}
	}
};