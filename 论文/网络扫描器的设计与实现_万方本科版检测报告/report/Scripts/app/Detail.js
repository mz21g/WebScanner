var viewModel = {
    copyPercentGraph: ko.observable(),
    originalCharacterTotal: ko.observable(),
    originalParagraphTotal: ko.observable(),
    copyPercents: ko.observable({
        totalCopyPercent: 0,
        referenceCopyPercent: 0,
        degreeCopyPercent: 0,
        publishedCopyPercent: 0
    }),
    SimilarAuthors: ko.observable([]),
    SimilarArticles: ko.observable([]),
    SimilarFragments: ko.observable([]),
    SimilarFragment: ko.observable(),
    MaxCopyPercentArticle: ko.observable({}),

    similarAuthorsShow: ko.observable('table'),

    similarAuthorsToggle: function () {
        var self = this;

        if (self.similarAuthorsShow() == 'table') {
            self.similarAuthorsShow('graph');
        }
        else {
            self.similarAuthorsShow('table');
        }
    },

    similarArticlesShow: ko.observable('table'),

    similarArticlesToggle: function () {
        var self = this;

        if (self.similarArticlesShow() == 'table') {
            self.similarArticlesShow('graph');
        }
        else {
            self.similarArticlesShow('table');
        }
    }
};

