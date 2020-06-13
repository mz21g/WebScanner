ko.bindingHandlers.graphPie1 = {
    update: function (elem, valueAccessor) {
        var currentValue = ko.utils.unwrapObservable(valueAccessor());

        var chart = echarts.init(elem);
        chart.setOption({
            //tooltip: {
            //    trigger: 'item',
            //    formatter: "{a} <br/>{b}: {c} ({d}%)"
            //},
            series: [
                {
                    name: '',
                    type: 'pie',
                    radius: ['65%', '100%'],
                    hoverAnimation: false,
                    label: {
                        normal: {
                            show: true,
                            position: 'center',
                            textStyle: {
                                fontSize: '20',
                                fontWeight: 'bold',
                            }
                        }
                        //,
                        //emphasis: {
                        //    show: true,
                        //    textStyle: {
                        //        fontSize: '30',
                        //        fontWeight: 'bold'
                        //    }
                        //}
                    },
                    labelLine: {
                        normal: {
                            show: false
                        }
                    },
                    data: [
                        {
                            value: currentValue,
                            name: currentValue + '%',
                            itemStyle: {
                                normal: {
                                    color: '#26B1C1'
                                }
                            }
                        },
                        {
                            value: (100 - currentValue),
                            name: '',
                            itemStyle: {
                                normal: {
                                    color: '#9FEAF3'
                                }
                            }
                        }
                    ]
                }
            ]
        });
    }
};

ko.bindingHandlers.numeral = {
    update: function (elem, valueAccessor) {

        var currentValue = ko.utils.unwrapObservable(valueAccessor());
        if (typeof (currentValue) != 'object') {
            currentValue = { value: currentValue, format: '0,0' };
        }

        var formattedValue = numeral(currentValue.value).format(currentValue.format);
        $(elem).text(formattedValue);
    }
};

ko.components.register('graph-bar', {
    viewModel: { require: app.root + 'Scripts/app/components/component-graph-bar.js' },
    template: { require: 'text!' + app.root + 'Scripts/app/components/component-graph-bar.html' }
});

ko.components.register('graph-bar2', {
    viewModel: { require: app.root + 'Scripts/app/components/component-graph-bar.js' },
    template: '<div style="width:650px; height:225px;margin-top:20px;margin-bottom:20px;" class="graphBar">    <!-- 横线 -->    <div class="hline" style="width:600px;top:5px; left:50px;"></div>    <div class="hline" style="width:600px; top: 60px;left:50px;"></div>    <div class="hline" style="width:600px; top: 115px;left:50px;"></div>    <div class="hline" style="width:600px; top: 170px;left:50px;"></div>    <div class="hline" style="width:600px; top: 225px;left:50px;"></div>    <!-- 纵线 -->    <div class="vline" style="height:220px;left:80px;top:5px;"></div>    <div class="vline" style="height:220px;left:140px;top:5px;"></div>    <div class="vline" style="height:220px;left:200px;top:5px;"></div>    <div class="vline" style="height:220px;left:260px;top:5px;"></div>    <div class="vline" style="height:220px;left:320px;top:5px;"></div>    <div class="vline" style="height:220px;left:380px;top:5px;"></div>    <div class="vline" style="height:220px;left:440px;top:5px;"></div>    <div class="vline" style="height:220px;left:500px;top:5px;"></div>    <div class="vline" style="height:220px;left:560px;top:5px;"></div>    <div class="vline" style="height:220px;left:620px;top:5px;"></div>    <!-- 虚线 -->    <div data-bind="style:{ top: (height - totalCopyPercent* yscale) + \'px\' }" style="width: 600px;left: 50px;border-bottom: dashed 1px #ddd;background-color: none;height: 0px;"></div>    <span data-bind="style:{ top: (height - totalCopyPercent* yscale - 10) + \'px\'}, text: totalCopyPercent + \'%\'" style="left: 625px;"></span>    <!-- y轴刻度 -->    <!-- ko foreach: yarray -->    <span class="ylabel" data-bind="text:$data + \'%\' , style:{ top: ($parent.height - $parent.baseY* $parent.yscale * (4-$index()) - 5) + \'px\' }"></span>    <!-- /ko -->    <!-- 参考文献相似比 -->    <div class="bg-reference bar"         style="left:200px;"         data-bind="style:{            height: referenceCopyPercent * yscale + \'px\',            top: (height - totalCopyPercent * yscale) + \'px\'}"></div>    <div class="bg-others bar"         style="left:200px;"         data-bind="style:{            height: (totalCopyPercent - referenceCopyPercent) * yscale + \'px\',            top: (height - (totalCopyPercent - referenceCopyPercent) * yscale) + \'px\'}"></div>    <!-- 本人已发表论文相似比 -->    <div class="bg-published bar"         style="left:440px;"         data-bind="style:{            height: publishedCopyPercent * yscale + \'px\',            top: (height - totalCopyPercent * yscale) + \'px\'}"></div>    <div class="bg-others bar"         style="left:440px;"         data-bind="style:{            height: (totalCopyPercent - publishedCopyPercent) * yscale + \'px\',            top: (height - (totalCopyPercent - publishedCopyPercent) * yscale) + \'px\'}"></div>    <!-- 参考文献相似比 -->    <span class="glyphicon glyphicon-arrow-left label-arrow"          style="left: 265px;"          data-bind="style:{top: (height - (totalCopyPercent - referenceCopyPercent/2) * yscale - 5) + \'px\'}"></span>    <div class="label-block" style="left: 270px;height:40px;"         data-bind="style:{top: (height - (totalCopyPercent - referenceCopyPercent/2) * yscale - 17) + \'px\'}">        参考文献相似比        <br />        <div data-bind="text: referenceCopyPercent + \'%\'"></div>    </div>    <span class="glyphicon glyphicon-arrow-left label-arrow"          style="left: 265px;"          data-bind="style:{top: (height - ((totalCopyPercent - referenceCopyPercent)/2) * yscale - 5) + \'px\'}"></span>    <div class="label-block"         style="left: 270px;height:60px;"         data-bind="style:{top: (height - ((totalCopyPercent - referenceCopyPercent)/2) * yscale - 18) + \'px\'}">        辅助排除参考文<br />献相似比        <br />        <div data-bind="text: (totalCopyPercent - referenceCopyPercent).toFixed(2) + \'%\'"></div>    </div>    <!-- 本人已发表论文相似比 -->    <span class="glyphicon glyphicon-arrow-left label-arrow" style="left: 505px;"          data-bind="style:{top: (height - (totalCopyPercent - publishedCopyPercent/2) * yscale - 5) + \'px\'}"></span>    <div class="label-block" style="left: 510px;height:60px;"         data-bind="style:{top: (height - (totalCopyPercent - publishedCopyPercent/2) * yscale - 18) + \'px\'}">        可能引用本人已        <br />        发表论文相似比        <br />        <div data-bind="text: publishedCopyPercent + \'%\'"></div>    </div>    <span class="glyphicon glyphicon-arrow-left label-arrow" style="left: 505px;"          data-bind="style:{top: (height - ((totalCopyPercent - publishedCopyPercent)/2) * yscale - 5) + \'px\'}"></span>    <div class="label-block" style="left: 510px;height:60px;"         data-bind="style:{top: (height - ((totalCopyPercent - publishedCopyPercent)/2) * yscale - 18) + \'px\'}">        辅助排除本人已        <br />        发表论文相似比        <br />        <div data-bind="text: (totalCopyPercent - publishedCopyPercent).toFixed(2) + \'%\'"></div>    </div></div>'
});

ko.components.register('bubble-cloud', {
    viewModel: { require: app.root + 'Scripts/app/components/component-bubble-cloud.js' },
    template: '<div class="bubbleCloud" data-bind="foreach: similarAuthors"><div style="cursor:pointer" class="bubblecloud-bubble" data-bind="attr: { id: \'bubble\' + $index(),\'data-index\': $index,\'data-text\': (CopyPercent * 100).toFixed(2) + \'%\'}, text: Author"></div><div class="bubblecloud-line"></div></div> '
});

//ko.components.register('rose-pie', {
//    viewModel: { require: app.root + 'Scripts/app/components/component-rose-pie.js' },
//    template: { require: 'text!' + app.root + 'Scripts/app/components/component-rose-pie.html' }
//});

ko.components.register('rose-pie', {
    viewModel: function (params) {
        var self = this;
        var color = ['#399cc3', '#ffb82a', '#3fcbdb', '#ff7373', '#d286de', '#26b1c1', '#7cd6a9', '#f9cc71'];
        var fontSize = [25, 22, 20, 18, 17, 15, 13, 12];
        var valueArray = [45,40,35,32.5,30,25,20,15]

        var data = _.map(_.first(params.value(), 8), function (item, index) {
            return {
                name: (item.copyPercent * 100).toFixed(2) + '%',
                value: valueArray[index], //item.copyPercent * 100,
                data: item,
                label: {
                    normal: {
                        textStyle: {
                            fontSize: fontSize[index],
                            fontWeight: 'bold'
                        }
                    }
                },
                itemStyle: {
                    normal: {
                        color: color[index],
                        shadowBlur: 10,
                        shadowColor: 'gray',
                        shadowOffsetX: 3,
                        shadowOffsetY: 3
                    }
                }
            }
        });

        // 属性
        self.isSelect = ko.observable(false),
        self.copyPercent = ko.observable(),
        self.title = ko.observable(),
        self.author = ko.observable(),
        self.isReference = ko.observable(),
        self.textClass = ko.observable(),
        self.ALink = ko.observable(),
        self.TLink = ko.observable(),
        self.hasBanquan = ko.observable(),
        self.option = {
            calculable: true,
            series: [
                {
                    name: '',
                    type: 'pie',
                    radius: [50, 170],
                    roseType: 'radius',
                    startAngle: '45',
                    center: ['50%', '50%'],
                    clockwise: false,
                    label: {
                        normal: {
                            show: true,
                            position: 'inside'
                        }
                    },
                    data: data
                }
            ]
        };

        // 方法
        self.init = function () {
            var ele = $('#' + params.id + ' .rosePieChart')[0];
            var chart = echarts.init(ele);
            chart.setOption(self.option);

            chart.on('mouseover', function (params) {
                var item = params.data.data;

                var textClass = 'text-others';
                if (item.isPublishedSelfCited) {
                    textClass = 'text-published';
                }
                else if (item.isUnPublishedSelfCited) {
                    textClass = 'text-degree';
                }
                else if (item.isReference) {
                    textClass = 'text-reference';
                }

                self.copyPercent((item.copyPercent * 100).toFixed('2') + '%');
                self.title(item.title[0]);
                self.author(item.creator[0]);
                self.isReference(item.isReference ? '是' : '否');
                self.textClass(textClass);
                var alink = "javascript:void(0)";
                if (item.creator[0] != "无") {
                    alink = app.AuthorLink + 'searchParam=' + item.creator[0]
                }
                self.ALink(alink);
                if (ArticleId(item.DBID, item) != undefined) {
                    if (ArticleType(item.DBID) == "wangwen") {
                        self.TLink(ArticleId(item.DBID, item).value);
                    }
                    else {
                        self.TLink(app.TitleLink + "_type=" + ArticleType(item.DBID) + "&id=" + ArticleId(item.DBID, item).value);
                    }
                }
                var hasBanquan = true;
                var hasBanquanKV = _.find(item.dataBaseInfoMap, function (item) { return item.key == '有无版权' });
                if (!hasBanquanKV || hasBanquanKV.value != "1") {
                    hasBanquan = false;
                }

                if (!hasBanquan) {
                    self.textClass('text-nocopyright');
                    self.ALink("javascript:void(0)");
                    self.TLink("javascript:void(0)");
                }

                self.isSelect(true);
                self.hasBanquan(hasBanquan);

                //console.log(params.data.data);
            });
        }

        self.init();

    },
    template: '<div class="rosePie">    <div class="rosePieChart"></div>    <div class="rosePieTable" data-bind="visible: isSelect"><table class="table table-bordered table-sm" style="width:480px;"><thead><tr><th style="width:15%;">相似比</th><th style="text-align:initial;">题名</th>                    <th style="width:15%;">作者</th>                    <th style="width:15%;">是否引用</th>                </tr>            </thead>            <tbody>                <tr data-bind="attr:{ \'class\': textClass }">                    <td style="text-align:center;" data-bind="text: copyPercent"></td>                    <td><a style="color: inherit;" data-bind="text: title, attr: { href: TLink ,target: \'_blank\', \'class\': !hasBanquan ? \'text-nocopyright\' : \'textClass\'}"></a></td>                    <td style="text-align:center; "><a style="color: inherit;" data-bind="text: author, attr: { href: ALink ,target: \'_blank\', \'class\': !hasBanquan ? \'text-nocopyright\' : \'textClass\'}"></a></td>                    <td style="text-align:center;" data-bind="text: isReference"></td>                </tr>            </tbody>        </table>    </div>    <div class="clearfix"></div></div>'
});

ko.components.register('copypercent-ring', {
    viewModel: { require: app.root + 'Scripts/app/components/component-copypercent-ring.js' },
    template: { require: 'text!' + app.root + 'Scripts/app/components/component-copypercent-ring.html' }
});

ko.components.register('like-widget', {
    viewModel: { require: app.root + 'Scripts/app/components/component-like-widget.js' },
    template: { require: 'text!' + app.root + 'Scripts/app/components/component-like-widget.html' }
});

//ko.components.register('like-widget', {
//    viewModel: function (params) {
//        // Data: value is either null, 'like', or 'dislike'
//        this.chosenValue = params.value;

//        // Behaviors
//        this.like = function () { this.chosenValue('like'); }.bind(this);
//        this.dislike = function () { this.chosenValue('dislike'); }.bind(this);
//    },
//    template:
//        '<div class="like-or-dislike" data-bind="visible: !chosenValue()">\
//            <button data-bind="click: like">Like it</button>\
//            <button data-bind="click: dislike">Dislike it</button>\
//        </div>\
//        <div class="result" data-bind="visible: chosenValue">\
//            You <strong data-bind="text: chosenValue"></strong> it\
//        </div>'
//});