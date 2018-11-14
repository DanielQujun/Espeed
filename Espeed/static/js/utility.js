
function lacation() {
    alert("开始获取地址")
    wx.getLocation({
        type: 'wgs84', // 默认为wgs84的gps坐标，如果要返回直接给openLocation用的火星坐标，可传入'gcj02'
        success: function (res) {
            var $latitude = res.latitude; // 纬度，浮点数，范围为90 ~ -90
            var $longitude = res.longitude; // 经度，浮点数，范围为180 ~ -180。
            var $speed = res.speed; // 速度，以米/每秒计
            var $accuracy = res.accuracy; // 位置精度

            alert("获取成功")

            //转换为街道地址，写入页面中
            getBaiduPosition($longitude,$latitude)

        }
    });
}

//调用百度api转化坐标系
function getBaiduPosition(lng,lat) {
    alert("开始转化坐标")
    var url ="http://api.map.baidu.com/geoconv/v1/?coords="+lng+","+lat+"&from=1&to=5&ak=BVbS3AVAs8iNor6NGxKfc1gG5OcqTxBu";
    $.ajax({
        url: url,
        type: 'GET',
        contentType: "application/json",
        dataType: 'jsonp',//这里要用jsonp的方式不然会报错
        success: function(data){

            //将转化完的坐标，写入session中，方便ajax发送已经转化过了的地址信息；
            $.session.set('latitude', data.result[0].y);
            $.session.set('longitude', data.result[0].x);
            alert( $.session.getItem('latitude'));
            alert( $.session.getItem('longitude'));
            // 根据坐标得到地址描述
            myGeo.getLocation(new BMap.Point($.session.get("longitude"),$.session.get("latitude")), function (result) {
                if (result) {
                    //地址写入页面
                    alert("转化成功");
                    $("#location").text(result.address);
                } else {
                    $.alert("获取位置失败...","text");
                }
            });

        },
        error: function(obj) {
            alert(obj.status);
        }
    });
}

// 地址跳转
function goUrl(url) {
     location.href = '/'+ url +'/?openid='+ window.localStorage.getItem("openid");
}




