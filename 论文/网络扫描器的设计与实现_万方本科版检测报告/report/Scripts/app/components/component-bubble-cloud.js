define(['knockout'], function (ko) {

    function BubbleCloudViewModel(params) {
        var self = this;

        // 属性
        self.similarAuthors = [];

        // 方法
        self.init = function () {
            // 取前8
            var similarAuthorsByOrder = _.sortBy(params.value(), 'CopyPercent').reverse();

            self.similarAuthors = _.first(similarAuthorsByOrder, 8);

            //
            $('.bubbleCloud').on('mouseover', '>.bubblecloud-bubble', function () {
                var index = $(this).data('index');
                var text = $(this).data('text');

                $('.bubblecloud-line')
                    .addClass('bubblecloud-line' + index)
                    .text(text)
                    .show();
            }).on('mouseout', '>.bubblecloud-bubble', function () {
                var index = $(this).data('index');
                $('.bubblecloud-line').hide().removeClass('bubblecloud-line' + index);
            }).on('click', '>.bubblecloud-bubble', function () {
                var link = $(this).data('link');
                var author = $(this).text();
                if (author != "无" && link != "javascript:void(0)") {
                    window.open(link);
                }
            });
        }

        self.init();
    }

    return BubbleCloudViewModel;

});
