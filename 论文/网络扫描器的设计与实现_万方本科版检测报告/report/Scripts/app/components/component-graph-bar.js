define(['knockout'], function (ko) {

    // {type: 'PA' totalCopyPercent: 91.30, referenceCopyPercent: 0.00, degreeCopyPercent: 0.00, publishedCopyPercent: 0.00}
    function LikeWidgetViewModel(params) {
        var self = this;

        // 属性
        self.withDegree = params.withDegree;
        self.type = params.value().type;
        self.totalCopyPercent = params.value().totalCopyPercent;
        self.referenceCopyPercent = params.value().referenceCopyPercent;
        self.degreeCopyPercent = params.value().degreeCopyPercent;
        self.publishedCopyPercent = params.value().publishedCopyPercent;

        self.maxY = 0;
        self.baseY = 0;
        self.yscale = 0;

        self.width = 650;
        self.height = 225;
        self.yarray = [];

        // 方法
        self.init = function () {
            // 根据总相似比，计算纵轴
            var maxY = self.totalCopyPercent / 0.9;
            if (maxY > 100) {
                maxY = 100;
            }
            self.maxY = maxY;

            //
            var baseY = (maxY / 4);
            self.baseY = baseY;

            // 计算scale
            var yscale = (self.height - 5) / maxY;
            self.yscale = yscale;

            // yarray
            for (var i = 4; i >= 0; i--) {
                var value = baseY * i;
                if (value < 0.1) {
                    value = value.toFixed(2);
                } else if (value < 10) {
                    value = value.toFixed(1);
                }
                else {
                    value = value.toFixed(0);
                }

                self.yarray.push(value);
            }
        }

        self.init();
    }

    return LikeWidgetViewModel;
});
