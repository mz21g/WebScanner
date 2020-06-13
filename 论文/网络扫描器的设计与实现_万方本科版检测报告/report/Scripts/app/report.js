var dbid2ResourceId = 
{
    "期刊": "Periodical",
    "学位": "Thesis",
    "会议": "Conference"
};

function getLink(record)
{
    var href = '';
    var linkPrefix = dbid2ResourceId[record.DBID] ? dbid2ResourceId[record.DBID] : '';
    if (linkPrefix != '')
    {
        href = app.Setting.DomainConfig.D + linkPrefix + "_" + record.ArticleId + ".aspx";
    }
}
