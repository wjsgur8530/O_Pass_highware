// Set new default font family and font color to mimic Bootstrap's default styling
Chart.defaults.global.defaultFontFamily = 'Nunito', '-apple-system,system-ui,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif';
Chart.defaults.global.defaultFontColor = '#858796';

// Calculate labels for the days
function generateMonthlyLabels() {
  var labels = [];
  var [what_month, monthly_count] = generateMonthlyData();
  for (var i = 0; i < what_month.length; i++) {
    var label = what_month[i] + '월';
    labels.push(label);
  }
  return labels;
}

var ctx = document.getElementById("monthlyVisitorAreaChart");
var [what_month, monthly_count] = generateMonthlyData();
var labels = generateMonthlyLabels();

var myLineChart = new Chart(ctx, {
  type: 'line',
  data: {
    labels: labels,
    datasets: [{
      label: "방문자 수",
      lineTension: 0.3,
      backgroundColor: "rgba(25, 135, 84, 0.05)",
      borderColor: "rgba(25, 135, 84, 1)",
      pointRadius: 3,
      pointBackgroundColor: "rgba(25, 135, 84, 1)",
      pointBorderColor: "rgba(25, 135, 84, 1)",
      pointHoverRadius: 3,
      pointHoverBackgroundColor: "rgba(25, 135, 84, 1)",
      pointHoverBorderColor: "rgba(25, 135, 84, 1)",
      pointHitRadius: 10,
      pointBorderWidth: 2,
      data: monthly_count
    }],
  },
  options: {
    maintainAspectRatio: false,
    layout: {
      padding: {
        left: 10,
        right: 25,
        top: 25,
        bottom: 0
      }
    },
    scales: {
      xAxes: [{
        time: {
          unit: 'date'
        },
        gridLines: {
          display: false,
          drawBorder: false
        },
        ticks: {
          maxTicksLimit: 7
        }
      }],
      yAxes: [{
        ticks: {
          maxTicksLimit: 5,
          padding: 10,
          // Include a comma separator in the ticks
          callback: function(value, index, values) {
            return value.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
          }
        },
        gridLines: {
          color: "rgb(234, 236, 244)",
          zeroLineColor: "rgb(234, 236, 244)",
          drawBorder: false,
          borderDash: [2],
          zeroLineBorderDash: [2]
        }
      }],
    },
    legend: {
      display: false
    },
    tooltips: {
      backgroundColor: "rgb(255,255,255)",
      bodyFontColor: "#858796",
      titleMarginBottom: 10,
      titleFontColor: '#6e707e',
      titleFontSize: 14,
      borderColor: '#dddfeb',
      borderWidth: 1,
      xPadding: 15,
      yPadding: 15,
      displayColors: false,
      intersect: false,
      mode: 'index',
      caretPadding: 10,
      callbacks: {
        label: function(tooltipItem, chart) {
          var datasetLabel = chart.datasets[tooltipItem.datasetIndex].label || '';
          return datasetLabel + ': ' + tooltipItem.yLabel.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
        }
      }
    }
  }
});
